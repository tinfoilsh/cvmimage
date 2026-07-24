package main

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

type containerInputFields struct {
	privileged  bool
	capDrop     bool
	securityOpt bool
}

func (c *Container) UnmarshalYAML(node *yaml.Node) error {
	var fields containerInputFields
	if node.Kind == yaml.MappingNode {
		for index := 0; index < len(node.Content); index += 2 {
			switch node.Content[index].Value {
			case "<<":
				return fmt.Errorf("container YAML merge keys are unsupported")
			case "privileged":
				fields.privileged = true
			case "cap_drop":
				fields.capDrop = true
			case "security_opt":
				fields.securityOpt = true
			}
		}
	}
	type rawContainer Container
	var raw rawContainer
	if err := node.Decode(&raw); err != nil {
		return err
	}
	*c = Container(raw)
	c.inputFields = fields
	return nil
}

func validateContainerInputPolicy(index int, container *Container, debug bool) error {
	fields := container.inputFields
	if fields.privileged {
		return fmt.Errorf("containers[%d].privileged is unsupported", index)
	}
	if fields.capDrop {
		return fmt.Errorf("containers[%d].cap_drop is unsupported", index)
	}
	if fields.securityOpt {
		return fmt.Errorf("containers[%d].security_opt is unsupported", index)
	}
	if container.PidMode != "" {
		return fmt.Errorf("containers[%d].pid is unsupported", index)
	}
	if len(container.Devices) != 0 {
		return fmt.Errorf("containers[%d].devices is unsupported", index)
	}
	if container.IPC != "" && container.IPC != "private" && container.IPC != "host" {
		return fmt.Errorf("containers[%d].ipc must be private or host", index)
	}
	allowDebugDockerSocket := reservedDebugRuntimeEnabled(container.Name, debug)
	for volumeIndex, volume := range container.Volumes {
		if _, err := canonicalizeContainerVolume(volume, allowDebugDockerSocket); err != nil {
			return fmt.Errorf("containers[%d].volumes[%d] %w", index, volumeIndex, err)
		}
	}
	for capabilityIndex, capability := range container.CapAdd {
		if !allowedContainerCapability(capability) {
			return fmt.Errorf("containers[%d].cap_add[%d] capability %q is unsupported", index, capabilityIndex, capability)
		}
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
