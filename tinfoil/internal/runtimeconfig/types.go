package runtimeconfig

import sharedconfig "github.com/tinfoilsh/tinfoil-config"

type Config = sharedconfig.Config
type CVMNetworkConfig = sharedconfig.CVMNetworkConfig
type NetworkSpec = sharedconfig.NetworkSpec
type ModelSpec = sharedconfig.ModelSpec
type VolumeSpec = sharedconfig.VolumeSpec
type VolumeOverlay = sharedconfig.VolumeOverlay
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
