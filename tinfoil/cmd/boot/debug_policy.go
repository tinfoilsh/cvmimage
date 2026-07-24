package main

import (
	"fmt"
	"os"
	"strings"
)

const (
	kernelCmdlinePath = "/proc/cmdline"

	tinfoilConfigHashParam = "tinfoil-config-hash"
	tinfoilDebugParam      = "tinfoil-debug"

	reservedDebugContainerName = "tinfoil-ssh-installer"
	reservedDebugPort          = "2222/tcp"
	reservedDebugHostPort      = 2222
	reservedDebugSerialDevice  = "/dev/hvc1"
	debugDockerSocketBind      = "/run/docker.sock:/var/run/docker.sock"
)

type kernelCmdline struct {
	ConfigHash string
	Debug      bool
}

func readKernelCmdline() (kernelCmdline, error) {
	data, err := os.ReadFile(kernelCmdlinePath)
	if err != nil {
		return kernelCmdline{}, fmt.Errorf("reading %s: %w", kernelCmdlinePath, err)
	}
	return parseKernelCmdline(string(data)), nil
}

func parseKernelCmdline(cmdline string) kernelCmdline {
	var parsed kernelCmdline
	configPrefix := tinfoilConfigHashParam + "="

	for _, field := range strings.Fields(cmdline) {
		if value, found := strings.CutPrefix(field, configPrefix); found {
			if parsed.ConfigHash == "" {
				parsed.ConfigHash = value
			}
			continue
		}
		if field == tinfoilDebugParam+"=on" {
			parsed.Debug = true
		}
	}

	return parsed
}

func (cmdline kernelCmdline) requiredConfigHash() (string, error) {
	if cmdline.ConfigHash == "" {
		return "", fmt.Errorf("parameter %s not found in cmdline", tinfoilConfigHashParam)
	}
	return cmdline.ConfigHash, nil
}

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
