package main

import (
	"tinfoil/internal/runtimeconfig"
)

const (
	reservedDebugContainerName = runtimeconfig.ReservedDebugContainerName
	reservedDebugPort          = runtimeconfig.ReservedDebugPort
	reservedDebugHostPort      = runtimeconfig.ReservedDebugHostPort
	reservedDebugSerialDevice  = runtimeconfig.ReservedDebugSerialDevice
	debugDockerSocketBind      = "/run/docker.sock:/var/run/docker.sock"
)
