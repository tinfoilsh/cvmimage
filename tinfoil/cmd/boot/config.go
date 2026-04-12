package main

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/creasty/defaults"
	"gopkg.in/yaml.v3"

	"tinfoil/internal/boot"
	shimconfig "tinfoil/internal/config"
)

// Config represents the main configuration file
type Config struct {
	ShimRaw    map[string]interface{} `yaml:"shim"`
	ShimCfg    *shimconfig.Config     `yaml:"-"`
	Network    NetworkConfig          `yaml:"network"`
	CPUs       int                    `yaml:"cpus"`
	Memory     int                    `yaml:"memory"`
	GPUs       int                    `yaml:"gpus"`
	Models     []ModelSpec            `yaml:"models"`
	Containers []Container            `yaml:"containers"`
}

// NetworkConfig defines network-level firewall rules enforced via nftables.
// The shim's listen-port is always allowed implicitly.
type NetworkConfig struct {
	AllowedInboundPorts []int `yaml:"allowed-inbound-ports"`
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
	NetworkMode string      `yaml:"network_mode,omitempty"` // "host", "bridge", "none" (default: "bridge")
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

	// Parse config strictly so typos in security-relevant fields fail loudly
	// instead of silently falling back to defaults.
	var config Config
	dec := yaml.NewDecoder(bytes.NewReader(configData))
	dec.KnownFields(true)
	if err := dec.Decode(&config); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	if config.GPUs != 0 && config.GPUs != 1 && config.GPUs != 8 {
		return nil, fmt.Errorf("gpus must be 0, 1, or 8 (got %d)", config.GPUs)
	}

	if err := validateContainers(config.Containers, isDebugMode()); err != nil {
		return nil, fmt.Errorf("validating containers: %w", err)
	}

	shimCfg, err := parseShimConfig(config.ShimRaw)
	if err != nil {
		return nil, fmt.Errorf("parsing shim config: %w", err)
	}
	config.ShimCfg = shimCfg

	shimYAML, err := yaml.Marshal(shimCfg)
	if err != nil {
		return nil, fmt.Errorf("marshaling shim config: %w", err)
	}
	if err := os.WriteFile(boot.ShimConfigPath, shimYAML, 0644); err != nil {
		return nil, fmt.Errorf("writing shim config: %w", err)
	}

	if err := loadExternalConfig(); err != nil {
		log.Printf("Warning: external config not loaded: %v", err)
	}

	return &config, nil
}

func parseShimConfig(raw map[string]interface{}) (*shimconfig.Config, error) {
	var cfg shimconfig.Config
	if err := defaults.Set(&cfg); err != nil {
		return nil, fmt.Errorf("setting defaults: %w", err)
	}
	yamlBytes, err := yaml.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("marshaling: %w", err)
	}
	if err := yaml.Unmarshal(yamlBytes, &cfg); err != nil {
		return nil, fmt.Errorf("unmarshaling: %w", err)
	}
	return &cfg, nil
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

// isDebugMode reports whether the kernel cmdline contains tinfoil-debug=on.
// The cmdline is measured into RTMR[2] / the SNP launch digest, so debug mode
// is distinguishable to remote verifiers.
func isDebugMode() bool {
	v, err := getCmdlineParam("tinfoil-debug")
	return err == nil && v == "on"
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
