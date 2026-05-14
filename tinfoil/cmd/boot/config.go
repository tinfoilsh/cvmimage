package main

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"tinfoil/internal/boot"
	shimconfig "tinfoil/internal/config"
)

// Config represents the main configuration file
type Config struct {
	ShimRaw    yaml.Node          `yaml:"shim"`
	ShimCfg    *shimconfig.Config `yaml:"-"`
	Network    NetworkConfig      `yaml:"network"`
	CPUs       int                `yaml:"cpus"`
	Memory     int                `yaml:"memory"`
	GPUs       int                `yaml:"gpus"`
	Models     []ModelSpec        `yaml:"models"`
	Containers []Container        `yaml:"containers"`
}

// NetworkConfig defines network-level firewall rules enforced via nftables.
// The shim's listen-port is always allowed implicitly.
type NetworkConfig struct {
	AllowedInboundPorts []int `yaml:"allowed-inbound-ports"`
	// TrustedDomains is an allowlist of hostnames containers may reach over the
	// public internet. tinfoil-egress resolves each name to one or more IPs at
	// boot and refreshes every 60s. Cannot be combined with TrustAllDomains.
	TrustedDomains []string `yaml:"trusted-domains"`
	// TrustAllDomains opts the enclave into unrestricted public Internet egress.
	// RFC1918 / link-local destinations remain blocked; only public addresses
	// are reachable. Cannot be combined with a non-empty TrustedDomains.
	TrustAllDomains bool `yaml:"trust-all-domains"`
}

// ModelSpec represents a model pack specification
type ModelSpec struct {
	MPK string `yaml:"mpk"`
}

// Container represents a container to run (Docker Compose-compatible subset)
type Container struct {
	Name       string   `yaml:"name"`
	Image      string   `yaml:"image"`
	Command    []string `yaml:"command,omitempty"`
	Entrypoint []string `yaml:"entrypoint,omitempty"`
	WorkingDir string   `yaml:"working_dir,omitempty"`
	User       string   `yaml:"user,omitempty"`

	// Environment variables:
	// - "VAR" (string) = lookup VAR from external-config.yml
	// - "VAR: value" (map) = hardcoded value (attested)
	Env []interface{} `yaml:"env,omitempty"`

	// Secrets: list of keys to lookup from external-config.yml (sensitive)
	Secrets []string `yaml:"secrets,omitempty"`

	Volumes     []string    `yaml:"volumes,omitempty"` // "source:target[:opts]"
	Devices     []string    `yaml:"devices,omitempty"`
	CapAdd      []string    `yaml:"cap_add,omitempty"`
	CapDrop     []string    `yaml:"cap_drop,omitempty"`
	SecurityOpt []string    `yaml:"security_opt,omitempty"`
	Runtime     string      `yaml:"runtime,omitempty"`      // e.g., "nvidia"
	NetworkMode string      `yaml:"network_mode,omitempty"` // no longer honoured; flagged at parse time so legacy configs fail loud
	IPC         string      `yaml:"ipc,omitempty"`          // e.g., "host"
	PidMode     string      `yaml:"pid,omitempty"`          // "host" for host PID namespace
	GPUs        interface{} `yaml:"gpus,omitempty"`         // "all", "0,1,2,3", or count (int)

	// Resource limits
	ShmSize  string            `yaml:"shm_size,omitempty"`  // "2g"
	Memory   string            `yaml:"memory,omitempty"`    // "512m", "2g"
	CPUs     float64           `yaml:"cpus,omitempty"`      // 0.5, 2.0
	Tmpfs    map[string]string `yaml:"tmpfs,omitempty"`     // {"/tmp": "size=100m"}
	ReadOnly bool              `yaml:"read_only,omitempty"` // read-only rootfs

	// Lifecycle
	Restart     string       `yaml:"restart,omitempty"`      // "no", "always", "on-failure", "unless-stopped"
	StopSignal  string       `yaml:"stop_signal,omitempty"`  // "SIGTERM", "SIGQUIT"
	StopTimeout *int         `yaml:"stop_timeout,omitempty"` // seconds
	Healthcheck *Healthcheck `yaml:"healthcheck,omitempty"`
}

// Healthcheck defines container health monitoring
type Healthcheck struct {
	Test        []string `yaml:"test"`                   // ["CMD", "curl", "-f", "http://localhost/health"]
	Interval    string   `yaml:"interval,omitempty"`     // "30s"
	Timeout     string   `yaml:"timeout,omitempty"`      // "10s"
	Retries     int      `yaml:"retries,omitempty"`      // 3
	StartPeriod string   `yaml:"start_period,omitempty"` // "60s"
}

const (
	configDiskPath   = "/dev/disk/by-id/scsi-0QEMU_QEMU_HARDDISK_tinfoil-config"
	externalDiskPath = "/dev/disk/by-id/scsi-0QEMU_QEMU_HARDDISK_tinfoil-ext-config"
)

var supportedGPUCounts = map[int]bool{
	0: true,
	1: true,
	2: true,
	4: true,
	6: true,
	8: true,
}

func validateGPUCount(count int) error {
	if !supportedGPUCounts[count] {
		return fmt.Errorf("gpus must be one of 0, 1, 2, 4, 6, or 8 (got %d)", count)
	}
	return nil
}

// loadAndVerifyConfig reads the config from disk and verifies its hash
func loadAndVerifyConfig() (*Config, error) {
	if _, err := os.Stat(configDiskPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("config disk not found at %s", configDiskPath)
	}

	// Read config from disk device (strip null bytes)
	configData, err := readDiskAndStripNulls(configDiskPath)
	if err != nil {
		return nil, fmt.Errorf("reading config disk: %w", err)
	}

	// Verify hash against kernel cmdline
	expectedHash, err := getCmdlineParam("tinfoil-config-hash")
	if err != nil {
		return nil, fmt.Errorf("getting expected config hash: %w", err)
	}
	if !hexHashPattern.MatchString(expectedHash) {
		return nil, fmt.Errorf("invalid config hash format in cmdline: %s", expectedHash)
	}

	actualHash := sha256Hash(configData)
	if expectedHash != actualHash { // Public values: no constant time comparison
		return nil, fmt.Errorf("config hash mismatch: expected %s, got %s", expectedHash, actualHash)
	}
	log.Printf("Config hash verified: %s", actualHash)

	// Write verified config to ramdisk
	if err := os.WriteFile(boot.ConfigPath, configData, 0644); err != nil {
		return nil, fmt.Errorf("writing config to ramdisk: %w", err)
	}

	// Parse config
	var config Config
	if err := yaml.Unmarshal(configData, &config); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	if err := validateGPUCount(config.GPUs); err != nil {
		return nil, err
	}

	shimCfg, err := shimconfig.Decode(&config.ShimRaw)
	if err != nil {
		return nil, fmt.Errorf("parsing shim config: %w", err)
	}
	config.ShimCfg = shimCfg

	if shimCfg.UpstreamContainer == "" && len(config.Containers) > 0 {
		shimCfg.UpstreamContainer = config.Containers[0].Name
	}

	if err := validateNetwork(&config); err != nil {
		return nil, fmt.Errorf("network config: %w", err)
	}

	shimYAML, err := yaml.Marshal(shimCfg)
	if err != nil {
		return nil, fmt.Errorf("marshaling shim config: %w", err)
	}
	if err := os.WriteFile(boot.ShimConfigPath, shimYAML, 0644); err != nil {
		return nil, fmt.Errorf("writing shim config: %w", err)
	}

	if err := writeEgressConfig(&config); err != nil {
		return nil, fmt.Errorf("writing egress config: %w", err)
	}

	if err := loadExternalConfig(); err != nil {
		log.Printf("Warning: external config not loaded: %v", err)
	}

	return &config, nil
}

// writeEgressConfig persists just the trusted-domains list to the private
// ramdisk so tinfoil-egress can load it once at startup. No-op when
// trusted-domains is empty (the egress service isn't started in that case).
func writeEgressConfig(cfg *Config) error {
	if len(cfg.Network.TrustedDomains) == 0 {
		return nil
	}
	data, err := yaml.Marshal(struct {
		TrustedDomains []string `yaml:"trusted-domains"`
	}{TrustedDomains: cfg.Network.TrustedDomains})
	if err != nil {
		return fmt.Errorf("marshaling: %w", err)
	}
	return os.WriteFile(boot.EgressConfigPath, data, 0600)
}

// loadConfigFromRamdisk reads config directly from ramdisk without verification (for debugging)
func loadConfigFromRamdisk() (*Config, error) {
	data, err := os.ReadFile(boot.ConfigPath)
	if err != nil {
		return nil, fmt.Errorf("reading config from ramdisk: %w", err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	shimCfg, err := shimconfig.Decode(&config.ShimRaw)
	if err != nil {
		return nil, fmt.Errorf("parsing shim config: %w", err)
	}
	config.ShimCfg = shimCfg

	if err := validateNetwork(&config); err != nil {
		return nil, fmt.Errorf("network config: %w", err)
	}

	return &config, nil
}

func loadExternalConfig() error {
	if _, err := os.Stat(externalDiskPath); os.IsNotExist(err) {
		return fmt.Errorf("external config disk not found at %s", externalDiskPath)
	}

	data, err := readDiskAndStripNulls(externalDiskPath)
	if err != nil {
		return fmt.Errorf("reading external config disk: %w", err)
	}

	if err := os.WriteFile(boot.ExternalConfigPath, data, 0600); err != nil {
		return fmt.Errorf("writing external config: %w", err)
	}

	return nil
}

func getExternalConfig() (*shimconfig.ExternalConfig, error) {
	data, err := os.ReadFile(boot.ExternalConfigPath)
	if err != nil {
		return nil, fmt.Errorf("reading external config: %w", err)
	}

	var config shimconfig.ExternalConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("parsing external config: %w", err)
	}
	return &config, nil
}

// readDiskAndStripNulls reads a disk device and strips trailing null bytes
func readDiskAndStripNulls(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}

	data = bytes.TrimRight(data, "\x00")
	return data, nil
}

// getCmdlineParam extracts a parameter value from /proc/cmdline
func getCmdlineParam(param string) (string, error) {
	data, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		return "", fmt.Errorf("reading /proc/cmdline: %w", err)
	}

	prefix := param + "="

	for part := range strings.FieldsSeq(string(data)) {
		if value, found := strings.CutPrefix(part, prefix); found {
			return value, nil
		}
	}

	return "", fmt.Errorf("parameter %s not found in cmdline", param)
}
