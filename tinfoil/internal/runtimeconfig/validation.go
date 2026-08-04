package runtimeconfig

import (
	"fmt"
	"net"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/distribution/reference"

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
	debugManagerSocketBind    = "/run/tinfoil/containers.sock:/run/tinfoil/containers.sock"
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
	modelNames := make(map[string]int, len(config.Models))
	for index, model := range config.Models {
		if model.Name == "" {
			return fmt.Errorf("models[%d].name must not be empty", index)
		}
		if prior, found := modelNames[model.Name]; found {
			return fmt.Errorf("models[%d].name %q duplicates models[%d].name", index, model.Name, prior)
		}
		if _, err := ModelPackReference(model); err != nil {
			return fmt.Errorf("models[%d]: %w", index, err)
		}
		modelNames[model.Name] = index
	}
	seen := map[string]int{}
	volumeWriters := map[string]int{}
	for index := range config.Containers {
		container := &config.Containers[index]
		if prior, found := seen[container.Name]; found {
			return fmt.Errorf("containers[%d].name %q duplicates containers[%d].name", index, container.Name, prior)
		}
		seen[container.Name] = index
		if err := validateContainer(index, container, config.GPUs, modelNames, volumeWriters, debug); err != nil {
			return err
		}
	}
	return nil
}

func validateContainer(index int, container *Container, availableGPUs int, modelNames map[string]int, volumeWriters map[string]int, debug bool) error {
	lists := []struct {
		name  string
		count int
	}{
		{"command", len(container.Command)}, {"entrypoint", len(container.Entrypoint)}, {"env", len(container.Env)},
		{"secrets", len(container.Secrets)}, {"models", len(container.Models)}, {"volumes", len(container.Volumes)}, {"devices", len(container.Devices)},
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
	for destination := range container.Tmpfs {
		if destination != path.Clean(destination) || destination != "/tmp" && !strings.HasPrefix(destination, "/tmp/") {
			return fmt.Errorf("containers[%d].tmpfs destination %q must be /tmp or a clean path below /tmp", index, destination)
		}
	}
	if container.Healthcheck != nil && len(container.Healthcheck.Test) > maxHealthcheckTestEntries {
		return fmt.Errorf("containers[%d].healthcheck.test exceeds limit %d", index, maxHealthcheckTestEntries)
	}
	if err := validateContainerImage(index, container.Image, debug); err != nil {
		return err
	}
	if err := validateContainerPolicy(index, container, availableGPUs, volumeWriters, debug); err != nil {
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
	seenModels := map[string]bool{}
	for modelIndex, model := range container.Models {
		if _, found := modelNames[model]; !found {
			return fmt.Errorf("containers[%d].models[%d] references unknown model %q", index, modelIndex, model)
		}
		if seenModels[model] {
			return fmt.Errorf("containers[%d].models[%d] duplicates model %q", index, modelIndex, model)
		}
		seenModels[model] = true
	}
	return nil
}

func validateContainerImage(index int, image string, debug bool) error {
	if image == "" {
		return fmt.Errorf("containers[%d].image is required", index)
	}
	named, err := reference.ParseNormalizedNamed(image)
	if err != nil {
		return fmt.Errorf("containers[%d].image %q is invalid: %w", index, image, err)
	}
	if debug {
		return nil
	}
	if _, ok := named.(reference.Digested); !ok {
		return fmt.Errorf("containers[%d].image %q must include an immutable digest", index, image)
	}
	return nil
}

func validateContainerPolicy(index int, container *Container, availableGPUs int, volumeWriters map[string]int, debug bool) error {
	if container.inputFields.privileged {
		return fmt.Errorf("containers[%d].privileged is unsupported", index)
	}
	if container.inputFields.capDrop {
		return fmt.Errorf("containers[%d].cap_drop is unsupported", index)
	}
	if container.inputFields.securityOpt {
		return fmt.Errorf("containers[%d].security_opt is unsupported", index)
	}
	if container.ReadOnly != nil && !*container.ReadOnly && !ReservedDebugRuntimeEnabled(container.Name, debug) {
		return fmt.Errorf("containers[%d].read_only must not disable the read-only root filesystem", index)
	}
	if container.PidMode != "" {
		return fmt.Errorf("containers[%d].pid is unsupported", index)
	}
	if len(container.Devices) != 0 {
		return fmt.Errorf("containers[%d].devices is unsupported", index)
	}
	if container.IPC != "" && container.IPC != "private" && container.IPC != "none" {
		return fmt.Errorf("containers[%d].ipc must be private or none", index)
	}
	if container.Runtime != "" && container.Runtime != "nvidia" {
		return fmt.Errorf("containers[%d].runtime %q is unsupported", index, container.Runtime)
	}
	if err := validateGPUSelection(index, container.GPUs, availableGPUs); err != nil {
		return err
	}
	if container.GPUs != nil && container.Runtime != "nvidia" {
		return fmt.Errorf("containers[%d].gpus requires runtime: nvidia", index)
	}
	if container.Runtime == "nvidia" && container.GPUs == nil {
		return fmt.Errorf("containers[%d].runtime nvidia requires an explicit gpus selection", index)
	}
	for volumeIndex, volume := range container.Volumes {
		if ReservedDebugRuntimeEnabled(container.Name, debug) && (volume == debugDockerSocketBind || volume == debugManagerSocketBind) {
			continue
		}
		source, destination, writable, err := parseNamedVolume(volume)
		if err != nil {
			return fmt.Errorf("containers[%d].volumes[%d]: %w", index, volumeIndex, err)
		}
		if writable {
			if prior, found := volumeWriters[source]; found {
				if prior != index {
					return fmt.Errorf("containers[%d].volumes[%d] makes named volume %q writable after containers[%d]", index, volumeIndex, source, prior)
				}
			}
			volumeWriters[source] = index
		}
		for priorIndex, prior := range container.Volumes[:volumeIndex] {
			_, priorDestination, _, priorErr := parseNamedVolume(prior)
			if priorErr == nil && priorDestination == destination {
				return fmt.Errorf("containers[%d].volumes[%d] duplicates destination %q from volumes[%d]", index, volumeIndex, destination, priorIndex)
			}
		}
	}
	for capabilityIndex, capability := range container.CapAdd {
		if !slices.Contains([]string{"IPC_LOCK", "NET_BIND_SERVICE", "SYS_NICE"}, capability) {
			return fmt.Errorf("containers[%d].cap_add[%d] capability %q is unsupported", index, capabilityIndex, capability)
		}
	}
	return nil
}

func parseNamedVolume(volume string) (source, destination string, writable bool, err error) {
	parts := strings.Split(volume, ":")
	if len(parts) < 2 || len(parts) > 3 || !validNamedVolume(parts[0]) {
		return "", "", false, fmt.Errorf("must use source:destination[:ro|rw] with a named volume source")
	}
	destination = parts[1]
	if destination != path.Clean(destination) || destination != "/data" && !strings.HasPrefix(destination, "/data/") {
		return "", "", false, fmt.Errorf("destination %q must be /data or a clean path below /data", destination)
	}
	mode := "rw"
	if len(parts) == 3 {
		mode = parts[2]
	}
	if mode != "ro" && mode != "rw" {
		return "", "", false, fmt.Errorf("mode %q must be ro or rw", mode)
	}
	return parts[0], destination, mode == "rw", nil
}

func validateGPUSelection(index int, selection interface{}, available int) error {
	if selection == nil {
		return nil
	}
	if available < 1 {
		return fmt.Errorf("containers[%d].gpus is set but the configuration declares no GPUs", index)
	}
	switch value := selection.(type) {
	case int:
		if value < 1 || value > available {
			return fmt.Errorf("containers[%d].gpus count must be between 1 and %d", index, available)
		}
		return nil
	case string:
		if value == "all" {
			return nil
		}
		if value == "" {
			return fmt.Errorf("containers[%d].gpus must not be empty", index)
		}
		seen := map[int]bool{}
		for _, rawID := range strings.Split(value, ",") {
			if rawID == "" || strings.TrimSpace(rawID) != rawID {
				return fmt.Errorf("containers[%d].gpus contains an invalid device ID %q", index, rawID)
			}
			var id int
			if _, err := fmt.Sscanf(rawID, "%d", &id); err != nil || fmt.Sprintf("%d", id) != rawID {
				return fmt.Errorf("containers[%d].gpus contains an invalid device ID %q", index, rawID)
			}
			if id < 0 || id >= available {
				return fmt.Errorf("containers[%d].gpus device ID %d is outside 0..%d", index, id, available-1)
			}
			if seen[id] {
				return fmt.Errorf("containers[%d].gpus device ID %d is duplicated", index, id)
			}
			seen[id] = true
		}
		return nil
	default:
		return fmt.Errorf("containers[%d].gpus must be a positive count, all, or a comma-separated device list", index)
	}
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
