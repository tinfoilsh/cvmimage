package containers

import "tinfoil/internal/runtimeconfig"

type Config = runtimeconfig.Config
type Container = runtimeconfig.Container
type CVMNetworkConfig = runtimeconfig.CVMNetworkConfig
type Healthcheck = runtimeconfig.Healthcheck
type ModelSpec = runtimeconfig.ModelSpec
type NetworkSpec = runtimeconfig.NetworkSpec

const (
	reservedDebugContainerName = runtimeconfig.ReservedDebugContainerName
	reservedDebugPort          = runtimeconfig.ReservedDebugPort
	reservedDebugHostPort      = runtimeconfig.ReservedDebugHostPort
	reservedDebugSerialDevice  = runtimeconfig.ReservedDebugSerialDevice
	debugDockerSocketBind      = "/run/docker.sock:/var/run/docker.sock"
)

func reservedDebugRuntimeEnabled(containerName string, debug bool) bool {
	return runtimeconfig.ReservedDebugRuntimeEnabled(containerName, debug)
}

func hasReservedDebugContainer(config *Config) bool {
	for _, container := range config.Containers {
		if container.Name == reservedDebugContainerName {
			return true
		}
	}
	return false
}
