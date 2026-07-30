package main

import (
	"fmt"
	"strings"

	"tinfoil/internal/runtimeconfig"
)

func validateContainerInputPolicy(index int, container *Container, debug bool) error {
	config := &runtimeconfig.Config{Containers: []runtimeconfig.Container{*container}}
	if err := runtimeconfig.Validate(config, debug); err != nil {
		return err
	}
	return nil
}

func canonicalizeContainerVolume(volume string, allowDebugDockerSocket bool) (string, error) {
	if allowDebugDockerSocket && volume == debugDockerSocketBind {
		return volume, nil
	}

	source, _, found := strings.Cut(volume, ":")
	if found && validNamedVolume(source) {
		return volume, nil
	}

	return "", fmt.Errorf("must use a named volume source")
}

func allowedContainerCapability(capability string) bool {
	switch capability {
	case "CHOWN", "DAC_OVERRIDE", "IPC_LOCK", "KILL", "NET_BIND_SERVICE", "SETGID", "SETUID", "SYS_NICE", "SYS_RESOURCE":
		return true
	default:
		return false
	}
}

func validNamedVolume(name string) bool {
	if name == "" || name == "." || name == ".." {
		return false
	}
	for index := 0; index < len(name); index++ {
		character := name[index]
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' {
			continue
		}
		if index > 0 && (character == '_' || character == '.' || character == '-') {
			continue
		}
		return false
	}
	return true
}
