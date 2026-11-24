package runtimeconfig

import (
	"fmt"

	sharedconfig "github.com/tinfoilsh/tinfoil-config"
)

const (
	ReservedDebugContainerName = sharedconfig.ReservedDebugContainerName
	ReservedDebugPort          = sharedconfig.ReservedDebugPort
	ReservedDebugHostPort      = sharedconfig.ReservedDebugHostPort
)

type Config = sharedconfig.Config
type CVMNetworkConfig = sharedconfig.CVMNetworkConfig
type NetworkSpec = sharedconfig.NetworkSpec
type ModelSpec = sharedconfig.ModelSpec
type VolumeSpec = sharedconfig.VolumeSpec
type VolumeOverlay = sharedconfig.VolumeOverlay
type Container = sharedconfig.Container
type Healthcheck = sharedconfig.Healthcheck
type AttestedKey = sharedconfig.AttestedKey

const AttestedKeysContainerDir = sharedconfig.AttestedKeysContainerDir

func AdminSSH(config *Config, debug bool) (*sharedconfig.AdminSSHMapping, error) {
	if debug {
		return nil, nil
	}
	return sharedconfig.AdminSSH(config)
}

func options(debug bool) sharedconfig.Options {
	if debug {
		return sharedconfig.Options{Mode: sharedconfig.HostDebugMode}
	}
	return sharedconfig.Options{}
}

// Decode reads and validates a config. This runtime boots only JSON configs:
// the shared library reads a config that pins an earlier cvm-version as YAML,
// and that one is refused here.
func Decode(data []byte, debug bool) (*Config, error) {
	config, err := sharedconfig.Decode(data, options(debug))
	if err != nil {
		return nil, err
	}
	if !sharedconfig.RequiresJSON(config.CVMVersion) {
		return nil, fmt.Errorf("parsing config: this runtime takes a JSON config that pins cvm-version %s or later (got %q)", sharedconfig.JSONConfigMinVersion, config.CVMVersion)
	}
	return config, nil
}

func Validate(config *Config, debug bool) error {
	return sharedconfig.Validate(config, options(debug))
}

func ModelIsIsolated(config *Config, name string) bool {
	return sharedconfig.ModelIsIsolated(config, name)
}

func ReservedDebugRuntimeEnabled(containerName string, debug bool) bool {
	return sharedconfig.ReservedDebugRuntimeEnabled(containerName, options(debug))
}

func ShimUpstreamSet(config *Config) bool {
	return sharedconfig.ShimUpstreamSet(config)
}

func HasReservedDebugContainer(config *Config) bool {
	return sharedconfig.HasReservedDebugContainer(config)
}

func ParsePorts(ports []string) ([]sharedconfig.PortMapping, error) {
	return sharedconfig.ParsePorts(ports)
}

// SealOwner names the container allowed to extend the seal register and its
// uid. The shared config carries no field for this yet, so it is nobody.
func SealOwner(config *Config) (string, int, bool) {
	return "", 0, false
}
