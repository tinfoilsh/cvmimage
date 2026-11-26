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
type VolumeSpec = sharedconfig.VolumeSpec
type VolumeOverlay = sharedconfig.VolumeOverlay
type Container = sharedconfig.Container
type Healthcheck = sharedconfig.Healthcheck
type AttestedKey = sharedconfig.AttestedKey

const AttestedKeysContainerDir = sharedconfig.AttestedKeysContainerDir

// The host sockets that only the debug toolbox may mount. No config accepted
// as a workload can name them.
const (
	DebugDockerSocketBind  = "/run/docker.sock:/var/run/docker.sock"
	DebugManagerSocketBind = "/run/tinfoil/containers.sock:/run/tinfoil/containers.sock"
)

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

// Decode reads and validates a config. The shared library's root package
// reads only JSON configs, which pin the first JSON cvm-version or a later
// one, so YAML and earlier pins are refused.
func Decode(data []byte, debug bool) (*Config, error) {
	return sharedconfig.Decode(data, options(debug))
}

// DecodeMeasured reads the config the launch measured and reports whether the
// guest runs its debug policy.
//
// The policy is on when the measured command line asks for it, which only a
// locally built launch file does, or when the config holds the host's debug
// toolbox: the reserved container with one of the debug socket mounts. A
// config accepted as a workload cannot hold those mounts, so the toolbox is
// only ever in a config the host changed for a debug launch, and that config's
// digest, which the launch measures, is no published config's.
func DecodeMeasured(data []byte, cmdlineDebug bool) (*Config, bool, error) {
	debug := cmdlineDebug
	if !debug {
		if config, err := Decode(data, true); err == nil {
			debug = holdsDebugToolbox(config)
		}
	}
	config, err := Decode(data, debug)
	return config, debug, err
}

func holdsDebugToolbox(config *Config) bool {
	for _, container := range config.Containers {
		if container.Name != ReservedDebugContainerName {
			continue
		}
		for _, volume := range container.Volumes {
			if volume == DebugDockerSocketBind || volume == DebugManagerSocketBind {
				return true
			}
		}
	}
	return false
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
