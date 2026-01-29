package main

import (
	"fmt"
	"log"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config represents the main configuration file
type Config struct {
	ShimVersion string      `yaml:"shim-version"`
	Shim        ShimConfig  `yaml:"shim"`
	Models      []ModelSpec `yaml:"models"`
	Containers  []Container `yaml:"containers"`
}

// ShimConfig is stored as raw YAML to preserve all fields for tfshim
type ShimConfig map[string]interface{}

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
	NetworkMode string      `yaml:"network_mode,omitempty"` // "host", "bridge", "none" (default: "host")
	IPC         string      `yaml:"ipc,omitempty"`          // e.g., "host"
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
	ramdiskPath        = "/mnt/ramdisk"
	configPath         = "/mnt/ramdisk/config.yml"
	externalConfigPath = "/mnt/ramdisk/external-config.yml"
	configDiskPath     = "/dev/sdb"
	externalDiskPath   = "/dev/sdc"
)

// loadAndVerifyConfig reads the config from disk and verifies its hash
func loadAndVerifyConfig() (*Config, error) {
	// Check if config disk exists
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
	if err := os.WriteFile(configPath, configData, 0644); err != nil {
		return nil, fmt.Errorf("writing config to ramdisk: %w", err)
	}

	// Parse config
	var config Config
	if err := yaml.Unmarshal(configData, &config); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	// Also read external config if it exists
	if err := loadExternalConfig(); err != nil {
		log.Printf("Warning: external config not loaded: %v", err)
	}

	return &config, nil
}

// loadConfigFromRamdisk reads config directly from ramdisk without verification (for debugging)
func loadConfigFromRamdisk() (*Config, error) {
	data, err := os.ReadFile(configPath)
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
		return fmt.Errorf("external config disk not found")
	}

	data, err := readDiskAndStripNulls(externalDiskPath)
	if err != nil {
		return fmt.Errorf("reading external config disk: %w", err)
	}

	if err := os.WriteFile(externalConfigPath, data, 0600); err != nil {
		return fmt.Errorf("writing external config: %w", err)
	}

	return nil
}

// ExternalConfig represents the external configuration file structure
type ExternalConfig struct {
	Env     map[string]string `yaml:"env"`
	Secrets map[string]string `yaml:"secrets"`
}

func getExternalConfig() (*ExternalConfig, error) {
	data, err := os.ReadFile(externalConfigPath)
	if err != nil {
		return nil, fmt.Errorf("reading external config: %w", err)
	}

	var config ExternalConfig
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

	// Strip null bytes (config mounted as disk may have padding)
	data = []byte(strings.TrimRight(string(data), "\x00"))
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
