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
	debugDockerSocketBind      = "/run/docker.sock:/var/run/docker.sock"
)
