package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net/netip"
	"os"

	"tinfoil/internal/boot"
	shimconfig "tinfoil/internal/config"
	"tinfoil/internal/device"
	"tinfoil/internal/runtimeconfig"
)

type Config = runtimeconfig.Config
type CVMNetworkConfig = runtimeconfig.CVMNetworkConfig
type NetworkSpec = runtimeconfig.NetworkSpec
type ModelSpec = runtimeconfig.ModelSpec
type Container = runtimeconfig.Container
type Healthcheck = runtimeconfig.Healthcheck

const maxGPUCount = 8
const maxDiskPayloadBytes = 1 << 20

func validateGPUCount(count int) error {
	if count < 0 || count > maxGPUCount {
		return fmt.Errorf("gpus must be between 0 and %d (got %d)", maxGPUCount, count)
	}
	return nil
}

func validateModelCount(count int) error {
	if count < 0 || count > device.MaxModelDisks {
		return fmt.Errorf("models must contain at most %d entries (got %d)", device.MaxModelDisks, count)
	}
	return nil
}

func validateExternalNetwork(config *shimconfig.ExternalNetworkConfig) error {
	if config == nil {
		return fmt.Errorf("network section is required")
	}
	prefix, err := netip.ParsePrefix(config.Address)
	if err != nil || !prefix.Addr().Is4() {
		return fmt.Errorf("invalid IPv4 address %q", config.Address)
	}
	if prefix.Bits() > 30 {
		return fmt.Errorf("IPv4 prefix /%d has no distinct guest and gateway addresses", prefix.Bits())
	}
	gateway, err := netip.ParseAddr(config.Gateway)
	if err != nil || !gateway.Is4() {
		return fmt.Errorf("invalid IPv4 gateway %q", config.Gateway)
	}
	if !prefix.Contains(gateway) {
		return fmt.Errorf("gateway %s is outside address subnet %s", config.Gateway, config.Address)
	}

	address := prefix.Addr()
	network := prefix.Masked().Addr()
	broadcast := ipv4Broadcast(prefix)
	if gateway == network || gateway == broadcast {
		return fmt.Errorf("gateway %s is reserved in subnet %s", gateway, prefix)
	}
	if address == network ||
		address == broadcast ||
		address == gateway {
		return fmt.Errorf("address %s is reserved in subnet %s", address, prefix)
	}
	return nil
}

func ipv4Broadcast(prefix netip.Prefix) netip.Addr {
	broadcast := prefix.Masked().Addr().As4()
	for bit := prefix.Bits(); bit < 32; bit++ {
		broadcast[bit/8] |= 1 << (7 - bit%8)
	}
	return netip.AddrFrom4(broadcast)
}

// loadAndVerifyConfig reads the config from disk and verifies its hash
func loadAndVerifyConfig(expectedHash string, debug bool) (*Config, error) {
	configDiskPath, err := device.ConfigDisk()
	if err != nil {
		return nil, fmt.Errorf("finding config disk: %w", err)
	}

	configData, err := readDiskPayload(configDiskPath, maxDiskPayloadBytes)
	if err != nil {
		return nil, fmt.Errorf("reading config disk: %w", err)
	}

	// Verify hash against kernel cmdline
	if expectedHash == "" {
		return nil, fmt.Errorf("getting expected config hash: parameter tinfoil-config-hash not found in cmdline")
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

	config, err := runtimeconfig.Decode(configData, debug)
	if err != nil {
		return nil, err
	}

	if err := validateGPUCount(config.GPUs); err != nil {
		return nil, err
	}
	if err := validateModelCount(len(config.Models)); err != nil {
		return nil, err
	}

	if err := loadExternalConfig(); err != nil {
		return nil, err
	}

	return config, nil
}

func loadExternalConfig() error {
	externalDiskPath, err := device.ExternalConfigDisk()
	if err != nil {
		return fmt.Errorf("finding external config disk: %w", err)
	}

	data, err := readDiskPayload(externalDiskPath, maxDiskPayloadBytes)
	if err != nil {
		return fmt.Errorf("reading external config disk: %w", err)
	}
	if _, err := decodeExternalConfig(data); err != nil {
		return err
	}

	if err := os.WriteFile(boot.ExternalConfigPath, data, 0600); err != nil {
		return fmt.Errorf("writing external config: %w", err)
	}

	return nil
}

// externalConfigOrEmpty loads the external config, or returns an empty one
// when the disk is absent (bare dev launches without tinfoild metadata).
func externalConfigOrEmpty() *shimconfig.ExternalConfig {
	config, err := getExternalConfig()
	if err != nil {
		log.Printf("Warning: external config not available, using defaults: %v", err)
		return &shimconfig.ExternalConfig{}
	}
	return config
}

func getExternalConfig() (*shimconfig.ExternalConfig, error) {
	data, err := os.ReadFile(boot.ExternalConfigPath)
	if err != nil {
		return nil, fmt.Errorf("reading external config: %w", err)
	}

	return decodeExternalConfig(data)
}

func decodeExternalConfig(data []byte) (*shimconfig.ExternalConfig, error) {
	config, err := shimconfig.DecodeExternal(data)
	if err != nil {
		return nil, fmt.Errorf("parsing external config: %w", err)
	}
	if err := validateExternalNetwork(config.Network); err != nil {
		return nil, fmt.Errorf("external network config: %w", err)
	}
	return config, nil
}

// readDiskPayload reads a NUL-padded config disk without reading its full
// capacity into memory. Embedded non-NUL bytes after padding are rejected.
func readDiskPayload(path string, maxBytes int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", path, err)
	}
	defer file.Close()

	data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	if padding := bytes.IndexByte(data, 0); padding >= 0 {
		for _, value := range data[padding:] {
			if value != 0 {
				return nil, fmt.Errorf("%s contains data after NUL padding", path)
			}
		}
		return data[:padding], nil
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("%s payload exceeds %d bytes", path, maxBytes)
	}
	return data, nil
}
