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

func reservedDebugRuntimeEnabled(containerName string, debug bool) bool {
	return debug && containerName == reservedDebugContainerName
}

func hasReservedDebugContainer(config *Config) bool {
	for _, container := range config.Containers {
		if container.Name == reservedDebugContainerName {
			return true
		}
	}
	return false
}
