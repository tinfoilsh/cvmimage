package main

import (
	"tinfoil/internal/runtimeconfig"
)

const (
	reservedDebugContainerName = runtimeconfig.ReservedDebugContainerName
	reservedDebugPort          = runtimeconfig.ReservedDebugPort
	reservedDebugHostPort      = runtimeconfig.ReservedDebugHostPort
	debugDockerSocketBind      = "/run/docker.sock:/var/run/docker.sock"
)
