package runtimeconfig

import (
	sharedconfig "github.com/tinfoilsh/tinfoil-config"

	"tinfoil/internal/containernet"
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

type PortMapping = sharedconfig.PortMapping

func ParsePorts(ports []string) ([]PortMapping, error) {
	return sharedconfig.ParsePorts(ports)
}

// AttachOrder returns the bridges to connect to a container. Docker needs
// the first network at ContainerCreate time, so it's returned separately.
// The egress-capable network (if any) goes first; shim-net is appended
// last for the shim's upstream. The first network is also the one Docker
// publishes `ports:` on, so the firewall derives its DNAT rules from it.
func AttachOrder(c Container, cfg *Config) (first string, rest []string) {
	var egress string
	var closed []string
	for _, n := range c.Networks {
		if cfg.Networks[n].Egress != "closed" {
			egress = n
			continue
		}
		closed = append(closed, n)
	}
	if egress != "" {
		first = egress
		rest = append(rest, closed...)
	} else if len(closed) > 0 {
		first = closed[0]
		rest = append(rest, closed[1:]...)
	}
	if ShimUpstreamSet(cfg) && c.Name == cfg.ShimCfg.UpstreamContainer {
		if first == "" {
			first = containernet.ShimNetName
		} else {
			rest = append(rest, containernet.ShimNetName)
		}
	}
	return first, rest
}
