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
	return parseKernelCmdline(string(data))
}

func parseKernelCmdline(cmdline string) (kernelCmdline, error) {
	var parsed kernelCmdline
	debugSeen := false

	configPrefix := tinfoilConfigHashParam + "="
	debugPrefix := tinfoilDebugParam + "="

	for _, field := range strings.Fields(cmdline) {
		if value, found := strings.CutPrefix(field, configPrefix); found {
			if parsed.ConfigHash == "" {
				parsed.ConfigHash = value
			}
			continue
		}

		if field == tinfoilDebugParam {
			return kernelCmdline{}, fmt.Errorf("malformed kernel command-line parameter %s", tinfoilDebugParam)
		}

		value, found := strings.CutPrefix(field, debugPrefix)
		if !found {
			continue
		}
		if debugSeen {
			return kernelCmdline{}, fmt.Errorf("duplicate kernel command-line parameter %s", tinfoilDebugParam)
		}
		debugSeen = true
		if value != "on" {
			return kernelCmdline{}, fmt.Errorf("invalid kernel command-line parameter %s=%q", tinfoilDebugParam, value)
		}
		parsed.Debug = true
	}

	return parsed, nil
}

func (cmdline kernelCmdline) requiredConfigHash() (string, error) {
	if cmdline.ConfigHash == "" {
		return "", fmt.Errorf("parameter %s not found in cmdline", tinfoilConfigHashParam)
	}
	return cmdline.ConfigHash, nil
}

func canonicalizeDebugDockerSocketBind(volume string) (string, bool) {
	if volume == debugDockerSocketBind {
		return volume, true
	}
	return "", false
}

func reservedDebugRuntimeEnabled(containerName string, debug bool) bool {
	return debug && containerName == reservedDebugContainerName
}

func hasReservedDebugContainer(config *Config) bool {
	if config == nil {
		return false
	}
	for _, container := range config.Containers {
		if container.Name == reservedDebugContainerName {
			return true
		}
	}
	return false
}
