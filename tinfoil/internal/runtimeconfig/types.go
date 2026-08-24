package runtimeconfig

import sharedconfig "github.com/tinfoilsh/tinfoil-config"

const (
	ReservedDebugContainerName = sharedconfig.ReservedDebugContainerName
	ReservedDebugPort          = sharedconfig.ReservedDebugPort
	ReservedDebugHostPort      = sharedconfig.ReservedDebugHostPort
)

type Config = sharedconfig.Config
type CVMNetworkConfig = sharedconfig.CVMNetworkConfig
type NetworkSpec = sharedconfig.NetworkSpec
type ModelSpec = sharedconfig.ModelSpec
type Container = sharedconfig.Container
type Healthcheck = sharedconfig.Healthcheck

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
