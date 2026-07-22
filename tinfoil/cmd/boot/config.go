package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net/netip"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"tinfoil/internal/boot"
	shimconfig "tinfoil/internal/config"
	"tinfoil/internal/device"
)

// Config represents the main configuration file
type Config struct {
	ShimRaw    yaml.Node               `yaml:"shim"`
	ShimCfg    *shimconfig.Config      `yaml:"-"`
	CVMNetwork CVMNetworkConfig        `yaml:"cvm-network"`
	Networks   map[string]*NetworkSpec `yaml:"networks"`
	CPUs       int                     `yaml:"cpus"`
	Memory     int                     `yaml:"memory"`
	GPUs       int                     `yaml:"gpus"`
	Models     []ModelSpec             `yaml:"models"`
	Containers []Container             `yaml:"containers"`
	VaultURL   string                  `yaml:"vault-url,omitempty"`
}

// CVMNetworkConfig scopes host-firewall knobs that affect the CVM as a
// whole, distinct from per-bridge `networks:`.
type CVMNetworkConfig struct {
	// InboundPorts is the TCP-port allowlist on the CVM's external
	// interface beyond the shim's :443 (which is always open).
	InboundPorts []int `yaml:"inbound-ports"`
}

// NetworkSpec is one entry in the top-level `networks:` map. Egress
// defaults to "closed" via UnmarshalYAML so `name: {}` is a one-line
// closed bridge.
type NetworkSpec struct {
	Egress string   `yaml:"egress"`
	Allow  []string `yaml:"allow"`
}

func (n *NetworkSpec) UnmarshalYAML(node *yaml.Node) error {
	// `name:` with a null scalar body decodes to a ScalarNode here.
	if node.Kind == yaml.ScalarNode {
		n.Egress = "closed"
		return nil
	}
	type alias NetworkSpec
	var raw alias
	if err := node.Decode(&raw); err != nil {
		return err
	}
	*n = NetworkSpec(raw)
	if n.Egress == "" {
		n.Egress = "closed"
	}
	return nil
}

// ModelSpec represents a model pack specification.
type ModelSpec struct {
	Name      string `yaml:"name,omitempty"`
	MPK       string `yaml:"mpk,omitempty"` // Legacy alias for mwp.
	MWP       string `yaml:"mwp,omitempty"`
	EMWP      string `yaml:"emwp,omitempty"`
	KeySecret string `yaml:"key-secret,omitempty"`
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
	SecurityOpt []string    `yaml:"security_opt,omitempty"`
	Runtime     string      `yaml:"runtime,omitempty"`  // e.g., "nvidia"
	Networks    []string    `yaml:"networks,omitempty"` // names of entries in top-level `networks:`
	IPC         string      `yaml:"ipc,omitempty"`      // e.g., "host"
	PidMode     string      `yaml:"pid,omitempty"`      // "host" for host PID namespace
	GPUs        interface{} `yaml:"gpus,omitempty"`     // "all", "0,1,2,3", or count (int)

	// Resource limits
	ShmSize string            `yaml:"shm_size,omitempty"` // "2g"
	Memory  string            `yaml:"memory,omitempty"`   // "512m", "2g"
	CPUs    float64           `yaml:"cpus,omitempty"`     // 0.5, 2.0
	Tmpfs   map[string]string `yaml:"tmpfs,omitempty"`    // {"/tmp": "size=100m"}
	// ReadOnly and PidsLimit are pointers so we can tell "operator left it
	// unset" (apply the hardened default) from "operator wrote false / 0".
	ReadOnly  *bool  `yaml:"read_only,omitempty"`
	PidsLimit *int64 `yaml:"pids_limit,omitempty"`

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
	if config.Version != 2 {
		return fmt.Errorf("unsupported external network version %d", config.Version)
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
	if len(config.Nameservers) == 0 || len(config.Nameservers) > 3 {
		return fmt.Errorf("external network requires 1 to 3 DNS servers")
	}
	seenNameservers := make(map[netip.Addr]struct{}, len(config.Nameservers))
	for _, value := range config.Nameservers {
		nameserver, err := netip.ParseAddr(value)
		if err != nil || !nameserver.Is4() {
			return fmt.Errorf("invalid IPv4 DNS server %q", value)
		}
		if _, duplicate := seenNameservers[nameserver]; duplicate {
			return fmt.Errorf("duplicate DNS server %q", value)
		}
		seenNameservers[nameserver] = struct{}{}
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
func loadAndVerifyConfig() (*Config, error) {
	configDiskPath, err := device.ConfigDisk()
	if err != nil {
		return nil, fmt.Errorf("finding config disk: %w", err)
	}

	configData, err := readDiskPayload(configDiskPath, maxDiskPayloadBytes)
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

	var config Config
	if err := yaml.Unmarshal(configData, &config); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	if err := validateGPUCount(config.GPUs); err != nil {
		return nil, err
	}
	if err := validateModelCount(len(config.Models)); err != nil {
		return nil, err
	}

	shimCfg, err := shimconfig.Decode(&config.ShimRaw)
	if err != nil {
		return nil, fmt.Errorf("parsing shim config: %w", err)
	}
	shimCfg.ExpectedGPUs = config.GPUs
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
		return nil, err
	}

	return &config, nil
}

// writeEgressConfig persists the per-allowlist-network FQDN map to the
// private ramdisk so tinfoil-egress can load it once at startup. No-op
// when no network has `egress: allowlist` (the daemon isn't started).
func writeEgressConfig(cfg *Config) error {
	out := egressFile{Networks: map[string]egressFileEntry{}}
	for name, spec := range cfg.Networks {
		if spec.Egress != "allowlist" {
			continue
		}
		out.Networks[name] = egressFileEntry{Allow: spec.Allow}
	}
	if len(out.Networks) == 0 {
		return nil
	}
	data, err := yaml.Marshal(out)
	if err != nil {
		return fmt.Errorf("marshaling: %w", err)
	}
	return os.WriteFile(boot.EgressConfigPath, data, 0600)
}

type egressFile struct {
	Networks map[string]egressFileEntry `yaml:"networks"`
}
type egressFileEntry struct {
	Allow []string `yaml:"allow"`
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
	if err := validateModelCount(len(config.Models)); err != nil {
		return nil, err
	}

	shimCfg, err := shimconfig.Decode(&config.ShimRaw)
	if err != nil {
		return nil, fmt.Errorf("parsing shim config: %w", err)
	}
	shimCfg.ExpectedGPUs = config.GPUs
	config.ShimCfg = shimCfg

	if err := validateNetwork(&config); err != nil {
		return nil, fmt.Errorf("network config: %w", err)
	}

	return &config, nil
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
