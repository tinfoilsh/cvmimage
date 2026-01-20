package main

import (
	"fmt"
	"log/slog"
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

// Container represents a container to run
type Container struct {
	Name  string      `yaml:"name"`
	Image string      `yaml:"image"`
	Args  interface{} `yaml:"args"` // Can be string or []string
}

// ExternalConfig represents the external configuration file
type ExternalConfig struct {
	GcloudKey      string `yaml:"gcloud-key"`
	GcloudRegistry string `yaml:"gcloud-registry"`
}

const (
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
	slog.Info("config hash verified", "hash", actualHash)

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
		slog.Warn("external config not loaded", "error", err)
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

func getExternalConfig() (*ExternalConfig, error) {
	data, err := os.ReadFile(externalConfigPath)
	if err != nil {
		return nil, err
	}

	var config ExternalConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	return &config, nil
}

// readDiskAndStripNulls reads a disk device and strips trailing null bytes
func readDiskAndStripNulls(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// Strip null bytes (config mounted as disk may have padding)
	data = []byte(strings.TrimRight(string(data), "\x00"))
	return data, nil
}

// getCmdlineParam extracts a parameter value from /proc/cmdline
func getCmdlineParam(param string) (string, error) {
	data, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		return "", err
	}

	prefix := param + "="

	for part := range strings.FieldsSeq(string(data)) {
		if value, found := strings.CutPrefix(part, prefix); found {
			return value, nil
		}
	}

	return "", fmt.Errorf("parameter %s not found in cmdline", param)
}
