package runtimeconfig

import (
	"slices"

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
type InboundMapping = sharedconfig.AdminSSHMapping

const AttestedKeysContainerDir = sharedconfig.AttestedKeysContainerDir

// InboundMappings resolves each published port that cvm-network.inbound-ports
// also lists. These bind on the guest interface; the debug toolbox profile
// binds none.
func InboundMappings(config *Config, debug bool) ([]InboundMapping, error) {
	if debug {
		return nil, nil
	}
	var mappings []InboundMapping
	for _, container := range config.Containers {
		ports, err := sharedconfig.ParsePorts(container.Ports)
		if err != nil {
			return nil, err
		}
		for _, port := range ports {
			if slices.Contains(config.CVMNetwork.InboundPorts, port.Host) {
				mappings = append(mappings, InboundMapping{Container: container.Name, GuestPort: port.Host, ContainerPort: port.Container})
			}
		}
	}
	return mappings, nil
}

func options(debug bool) sharedconfig.Options {
	if debug {
		return sharedconfig.Options{Mode: sharedconfig.HostDebugMode}
	}
	return sharedconfig.Options{}
}

func Decode(data []byte, debug bool) (*Config, error) {
	return sharedconfig.Decode(data, options(debug))
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
