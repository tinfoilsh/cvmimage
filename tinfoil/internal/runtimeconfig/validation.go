package runtimeconfig

import (
	"fmt"
	"net"
	"regexp"
	"slices"
	"strings"

	"tinfoil/internal/containernet"
	"tinfoil/internal/device"
)

const (
	maxConfigContainers       = 64
	maxConfigModels           = 64
	maxConfigNetworks         = 32
	maxConfigInboundPorts     = 64
	maxContainerListEntries   = 256
	maxContainerTmpfsEntries  = 64
	maxNetworkAllowEntries    = 256
	maxHealthcheckTestEntries = 64
	maxEnvironmentNameBytes   = 256
	maxHostnameLength         = 253
	maxBridgeNameLen          = 15
	debugDockerSocketBind     = "/run/docker.sock:/var/run/docker.sock"
)

var (
	validEgressModes       = []string{"closed", "allowlist", "open"}
	networkNamePattern     = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)
	rfc1123HostnamePattern = regexp.MustCompile(`^(?i)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
)

func Validate(config *Config, debug bool) error {
	if config.GPUs < 0 || config.GPUs > 8 {
		return fmt.Errorf("gpus must be between 0 and 8 (got %d)", config.GPUs)
	}
	if len(config.Models) > device.MaxModelDisks {
		return fmt.Errorf("models must contain at most %d entries (got %d)", device.MaxModelDisks, len(config.Models))
	}
	if err := validateShape(config, debug); err != nil {
		return err
	}
	return validateNetwork(config)
}

func validateShape(config *Config, debug bool) error {
	if len(config.Containers) > maxConfigContainers {
		return fmt.Errorf("containers exceeds limit %d", maxConfigContainers)
	}
	if len(config.Models) > maxConfigModels {
		return fmt.Errorf("models exceeds limit %d", maxConfigModels)
	}
	if len(config.Networks) > maxConfigNetworks {
		return fmt.Errorf("networks exceeds limit %d", maxConfigNetworks)
	}
	if len(config.CVMNetwork.InboundPorts) > maxConfigInboundPorts {
		return fmt.Errorf("cvm-network.inbound-ports exceeds limit %d", maxConfigInboundPorts)
	}
	for name, network := range config.Networks {
		if network != nil && len(network.Allow) > maxNetworkAllowEntries {
			return fmt.Errorf("networks.%s.allow exceeds limit %d", name, maxNetworkAllowEntries)
		}
	}
	seen := map[string]int{}
	for index := range config.Containers {
		container := &config.Containers[index]
		if prior, found := seen[container.Name]; found {
			return fmt.Errorf("containers[%d].name %q duplicates containers[%d].name", index, container.Name, prior)
		}
		seen[container.Name] = index
		if err := validateContainer(index, container, debug); err != nil {
			return err
		}
	}
	return nil
}

func validateContainer(index int, container *Container, debug bool) error {
	lists := []struct {
		name  string
		count int
	}{
		{"command", len(container.Command)}, {"entrypoint", len(container.Entrypoint)}, {"env", len(container.Env)},
		{"secrets", len(container.Secrets)}, {"volumes", len(container.Volumes)}, {"devices", len(container.Devices)},
		{"cap_add", len(container.CapAdd)}, {"networks", len(container.Networks)},
	}
	for _, list := range lists {
		if list.count > maxContainerListEntries {
			return fmt.Errorf("containers[%d].%s exceeds limit %d", index, list.name, maxContainerListEntries)
		}
	}
	if len(container.Tmpfs) > maxContainerTmpfsEntries {
		return fmt.Errorf("containers[%d].tmpfs exceeds limit %d", index, maxContainerTmpfsEntries)
	}
	if container.Healthcheck != nil && len(container.Healthcheck.Test) > maxHealthcheckTestEntries {
		return fmt.Errorf("containers[%d].healthcheck.test exceeds limit %d", index, maxHealthcheckTestEntries)
	}
	if err := validateContainerPolicy(index, container, debug); err != nil {
		return err
	}
	for envIndex, item := range container.Env {
		switch value := item.(type) {
		case string:
			if !validEnvironmentName(value) {
				return fmt.Errorf("containers[%d].env[%d] has invalid environment name %q", index, envIndex, value)
			}
		case map[string]interface{}:
			if len(value) != 1 {
				return fmt.Errorf("containers[%d].env[%d] must contain exactly one key", index, envIndex)
			}
			for key, scalar := range value {
				if !validEnvironmentName(key) {
					return fmt.Errorf("containers[%d].env[%d] has invalid environment name %q", index, envIndex, key)
				}
				switch scalar.(type) {
				case string, bool, int, uint64, float64:
				default:
					return fmt.Errorf("containers[%d].env[%d].%s must be a scalar", index, envIndex, key)
				}
			}
		default:
			return fmt.Errorf("containers[%d].env[%d] must be a name or one-key mapping", index, envIndex)
		}
	}
	for secretIndex, secret := range container.Secrets {
		if !validEnvironmentName(secret) {
			return fmt.Errorf("containers[%d].secrets[%d] has invalid environment name %q", index, secretIndex, secret)
		}
	}
	return nil
}

func validateContainerPolicy(index int, container *Container, debug bool) error {
	if container.inputFields.privileged {
		return fmt.Errorf("containers[%d].privileged is unsupported", index)
	}
	if container.inputFields.capDrop {
		return fmt.Errorf("containers[%d].cap_drop is unsupported", index)
	}
	if container.inputFields.securityOpt {
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
	for volumeIndex, volume := range container.Volumes {
		if ReservedDebugRuntimeEnabled(container.Name, debug) && volume == debugDockerSocketBind {
			continue
		}
		source, _, found := strings.Cut(volume, ":")
		if !found || !validNamedVolume(source) {
			return fmt.Errorf("containers[%d].volumes[%d] must use a named volume source", index, volumeIndex)
		}
	}
	for capabilityIndex, capability := range container.CapAdd {
		if !slices.Contains([]string{"CHOWN", "DAC_OVERRIDE", "IPC_LOCK", "KILL", "NET_BIND_SERVICE", "SETGID", "SETUID", "SYS_NICE", "SYS_RESOURCE"}, capability) {
			return fmt.Errorf("containers[%d].cap_add[%d] capability %q is unsupported", index, capabilityIndex, capability)
		}
	}
	return nil
}

func validateNetwork(config *Config) error {
	for _, port := range config.CVMNetwork.InboundPorts {
		if port < 1 || port > 65535 {
			return fmt.Errorf("cvm-network.inbound-ports: %d is not in 1..65535", port)
		}
	}
	for name, spec := range config.Networks {
		if err := validateNetworkEntry(name, spec); err != nil {
			return fmt.Errorf("networks.%s: %w", name, err)
		}
	}
	for index, container := range config.Containers {
		seen := map[string]bool{}
		egressCount := 0
		for _, name := range container.Networks {
			if seen[name] {
				return fmt.Errorf("containers[%d] %q: network %q listed twice", index, container.Name, name)
			}
			seen[name] = true
			if name == containernet.ShimNetName {
				return fmt.Errorf("containers[%d] %q: %q is reserved", index, container.Name, containernet.ShimNetName)
			}
			spec, ok := config.Networks[name]
			if !ok {
				return fmt.Errorf("containers[%d] %q: network %q not declared", index, container.Name, name)
			}
			if spec.Egress != "closed" {
				egressCount++
			}
		}
		if egressCount > 1 {
			return fmt.Errorf("containers[%d] %q: at most one attached network may have egress != closed", index, container.Name)
		}
	}
	if config.ShimCfg != nil && config.ShimCfg.UpstreamContainer != "" {
		for _, container := range config.Containers {
			if container.Name == config.ShimCfg.UpstreamContainer {
				return nil
			}
		}
		return fmt.Errorf("shim.upstream-container %q does not match any containers[].name", config.ShimCfg.UpstreamContainer)
	}
	return nil
}

func validateNetworkEntry(name string, spec *NetworkSpec) error {
	if name == "" {
		return fmt.Errorf("empty network name")
	}
	if name == containernet.ShimNetName {
		return fmt.Errorf("name %q is reserved", containernet.ShimNetName)
	}
	if len(name) > maxBridgeNameLen {
		return fmt.Errorf("name exceeds %d-char interface-name limit", maxBridgeNameLen)
	}
	if !networkNamePattern.MatchString(name) {
		return fmt.Errorf("name must be lowercase alphanumeric + hyphens (got %q)", name)
	}
	if !slices.Contains(validEgressModes, spec.Egress) {
		return fmt.Errorf("egress: %q is not one of closed | allowlist | open", spec.Egress)
	}
	if spec.Egress != "allowlist" && len(spec.Allow) > 0 {
		return fmt.Errorf("allow: only valid when egress: allowlist (got egress: %s)", spec.Egress)
	}
	for index, host := range spec.Allow {
		if host == "" {
			return fmt.Errorf("allow[%d] %q: empty entry", index, host)
		}
		if strings.Contains(host, "*") {
			return fmt.Errorf("allow[%d] %q: wildcards are reserved for future tinfoil-dns support", index, host)
		}
		if net.ParseIP(host) != nil {
			return fmt.Errorf("allow[%d] %q: IP literals are not allowed; use a hostname", index, host)
		}
		if len(host) > maxHostnameLength || !rfc1123HostnamePattern.MatchString(host) {
			return fmt.Errorf("allow[%d] %q: not a valid DNS hostname", index, host)
		}
	}
	return nil
}

func validEnvironmentName(name string) bool {
	if len(name) == 0 || len(name) > maxEnvironmentNameBytes {
		return false
	}
	for index := range len(name) {
		character := name[index]
		if character == '_' || character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' || index > 0 && character >= '0' && character <= '9' {
			continue
		}
		return false
	}
	return true
}
