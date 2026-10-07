package tinfoilconfig

import (
	_ "crypto/sha256" // Register the canonical OCI digest for standalone consumers.
	"fmt"
	"net"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/distribution/reference"
)

const (
	MaxModelDisks             = 24
	MaxAttestedKeys           = 32
	reservedShimNetworkName   = "shim-net"
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
	maxVolumeOwner            = 65534
	maxVolumeOverlays         = 8
	debugDockerSocketBind     = "/run/docker.sock:/var/run/docker.sock"
	debugManagerSocketBind    = "/run/tinfoil/containers.sock:/run/tinfoil/containers.sock"
)

// reservedHostPorts are the CVM's own listeners: a published port that
// collides with one would either fail to bind or shadow the shim.
var reservedHostPorts = map[int]string{
	443:                   "the shim",
	80:                    "ACME HTTP-01",
	ReservedDebugHostPort: "the debug toolbox",
}

var (
	validEgressModes       = []string{"closed", "allowlist", "open"}
	networkNamePattern     = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)
	rfc1123HostnamePattern = regexp.MustCompile(`^(?i)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	modelNamePattern       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	volumeNamePattern      = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
	attestedKeyIDPattern   = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
	cvmSourceRepoPattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9_][A-Za-z0-9._-]*$`)

	// An overlay source is a path inside a pack, so it may hold slashes, but
	// every segment begins with a non-dot to keep out `.` and `..`, and the
	// character class keeps out the comma and colon that delimit mount options.
	overlaySourcePattern = regexp.MustCompile(`^[A-Za-z0-9_-][A-Za-z0-9._-]*(/[A-Za-z0-9_-][A-Za-z0-9._-]*)*$`)
)

func Validate(config *Config, options Options) error {
	if err := validateCVMSource(config.CVMSource); err != nil {
		return err
	}
	if config.GPUs < 0 || config.GPUs > 8 {
		return fmt.Errorf("gpus must be between 0 and 8 (got %d)", config.GPUs)
	}
	if len(config.Models) > MaxModelDisks {
		return fmt.Errorf("models must contain at most %d entries (got %d)", MaxModelDisks, len(config.Models))
	}
	volumes, err := validateVolumes(config)
	if err != nil {
		return err
	}
	if err := validateShape(config, volumes, options); err != nil {
		return err
	}
	if err := validateNetwork(config); err != nil {
		return err
	}
	if err := ValidateAttestedKeys(config); err != nil {
		return err
	}
	_, err = AdminSSH(config)
	return err
}

// ValidateAttestedKeys checks declarations, exclusive grants, ownership and
// generated mount destinations. It is also used by the boot key store before
// deriving filesystem paths from a config.
func ValidateAttestedKeys(config *Config) error {
	if len(config.AttestedKeys) > MaxAttestedKeys {
		return fmt.Errorf("attested-keys exceeds limit %d", MaxAttestedKeys)
	}
	declared := make(map[string]bool, len(config.AttestedKeys))
	for i, key := range config.AttestedKeys {
		if !attestedKeyIDPattern.MatchString(key.ID) || key.ID == "tls" || key.ID == "hpke" {
			return fmt.Errorf("attested-keys[%d].id %q must be a safe lowercase name other than tls or hpke", i, key.ID)
		}
		if declared[key.ID] {
			return fmt.Errorf("attested-keys id %q is declared twice", key.ID)
		}
		declared[key.ID] = true
		switch key.Key {
		case KeyECDSAP256, KeyEd25519, KeyX25519:
		default:
			return fmt.Errorf("attested-keys[%d].key %q is unsupported", i, key.Key)
		}
		if key.UID < 0 || key.UID > 65534 || key.GID < 0 || key.GID > 65534 {
			return fmt.Errorf("attested-keys[%d] uid and gid must be between 0 and 65534", i)
		}
	}
	granted := make(map[string]string, len(declared))
	for _, container := range config.Containers {
		for _, id := range container.Keys {
			if !declared[id] {
				return fmt.Errorf("container %q grants unknown attested key %q", container.Name, id)
			}
			if prior, ok := granted[id]; ok {
				return fmt.Errorf("attested key %q is already granted to %q (duplicate or shared grant)", id, prior)
			}
			granted[id] = container.Name
		}
		if len(container.Keys) == 0 {
			continue
		}
		// Protect generated destinations in containers receiving keys.
		// Parent tmpfs /run is supported: Docker mounts nested key binds after it.
		for target := range container.Tmpfs {
			if overlapsKeyDir(target) && path.Clean(target) != "/run" {
				return fmt.Errorf("container %q tmpfs %q conflicts with attested key mounts", container.Name, target)
			}
		}
		for _, volume := range container.Volumes {
			_, target, ok := strings.Cut(volume, ":")
			if ok && overlapsKeyDir(target) {
				return fmt.Errorf("container %q volume target %q conflicts with attested key mounts", container.Name, target)
			}
		}
	}
	for _, key := range config.AttestedKeys {
		if _, ok := granted[key.ID]; !ok {
			return fmt.Errorf("attested key %q requires exactly one container grant", key.ID)
		}
	}
	return nil
}

func overlapsKeyDir(target string) bool {
	target = path.Clean(target)
	return target == "/" || target == AttestedKeysContainerDir ||
		strings.HasPrefix(target, AttestedKeysContainerDir+"/") ||
		strings.HasPrefix(AttestedKeysContainerDir, target+"/")
}

func validateVolumes(config *Config) (map[string]bool, error) {
	if disks := len(config.Models) + len(config.Volumes); disks > MaxModelDisks {
		return nil, fmt.Errorf("models and volumes must declare at most %d disks (got %d)", MaxModelDisks, disks)
	}
	execModels := make(map[string]bool, len(config.Models))
	for _, model := range config.Models {
		execModels[model.Name] = model.Exec
	}
	declared := make(map[string]bool, len(config.Volumes))
	for index, volume := range config.Volumes {
		if !volumeNamePattern.MatchString(volume.Name) {
			return nil, fmt.Errorf("volumes[%d].name %q must be lowercase alphanumeric with hyphens", index, volume.Name)
		}
		if declared[volume.Name] {
			return nil, fmt.Errorf("volumes[%d].name %q is declared twice", index, volume.Name)
		}
		if volume.Owner < 0 || volume.Owner > maxVolumeOwner {
			return nil, fmt.Errorf("volumes[%d].owner must be between 0 and %d (got %d)", index, maxVolumeOwner, volume.Owner)
		}
		if volume.KeySecret != "" && !validEnvironmentName(volume.KeySecret) {
			return nil, fmt.Errorf("volumes[%d].key-secret has invalid secret name %q", index, volume.KeySecret)
		}
		if _, err := volume.SizeBytes(); err != nil {
			return nil, fmt.Errorf("volumes[%d].size: %w", index, err)
		}
		if err := validateVolumeOverlays(index, &volume, execModels); err != nil {
			return nil, err
		}
		declared[volume.Name] = true
	}
	return declared, nil
}

func validateVolumeOverlays(index int, volume *VolumeSpec, execModels map[string]bool) error {
	if len(volume.Overlays) > maxVolumeOverlays {
		return fmt.Errorf("volumes[%d] declares more than %d overlays", index, maxVolumeOverlays)
	}
	if len(volume.Overlays) > 0 && !volume.Exec {
		return fmt.Errorf("volumes[%d] has overlays but is not exec", index)
	}
	targets := make(map[string]bool, len(volume.Overlays))
	for overlayIndex, overlay := range volume.Overlays {
		if !modelNamePattern.MatchString(overlay.Model) || !execModels[overlay.Model] {
			return fmt.Errorf("volumes[%d].overlays[%d] references unknown or non-exec model %q", index, overlayIndex, overlay.Model)
		}
		if !overlaySourcePattern.MatchString(overlay.Source) {
			return fmt.Errorf("volumes[%d].overlays[%d].source %q is not a pack-relative path", index, overlayIndex, overlay.Source)
		}
		// The target names a directory this volume's worker creates and mounts
		// on, so it stays a single segment: no separator can traverse out of the
		// volume, and no intermediate component can be a planted symlink.
		if !volumeNamePattern.MatchString(overlay.Target) {
			return fmt.Errorf("volumes[%d].overlays[%d].target %q must be a single lowercase name", index, overlayIndex, overlay.Target)
		}
		if targets[overlay.Target] {
			return fmt.Errorf("volumes[%d].overlays[%d].target %q is declared twice", index, overlayIndex, overlay.Target)
		}
		targets[overlay.Target] = true
	}
	return nil
}

func validateShape(config *Config, volumes map[string]bool, options Options) error {
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
	sealOwner := -1
	keySecrets := map[string]string{}
	for index, model := range config.Models {
		if model.Schema < 0 {
			return fmt.Errorf("models[%d].schema must be a positive integer", index)
		}
		if model.KeySecret == "" {
			continue
		}
		if !validEnvironmentName(model.KeySecret) {
			return fmt.Errorf("models[%d].key-secret has invalid secret name %q", index, model.KeySecret)
		}
		keySecrets[model.KeySecret] = fmt.Sprintf("models[%d]", index)
	}
	for index, volume := range config.Volumes {
		if volume.KeySecret != "" {
			keySecrets[volume.KeySecret] = fmt.Sprintf("volumes[%d]", index)
		}
	}
	for index := range config.Containers {
		container := &config.Containers[index]
		if prior, found := seen[container.Name]; found {
			return fmt.Errorf("containers[%d].name %q duplicates containers[%d].name", index, container.Name, prior)
		}
		seen[container.Name] = index
		if container.SealRegister {
			if sealOwner >= 0 {
				return fmt.Errorf("containers[%d].seal_register duplicates containers[%d].seal_register", index, sealOwner)
			}
			sealOwner = index
		}
		if err := validateContainer(index, container, config.GPUs, volumes, options); err != nil {
			return err
		}
		for secretIndex, secret := range container.Secrets {
			if owner, found := keySecrets[secret]; found {
				return fmt.Errorf("containers[%d].secrets[%d] %q exposes %s.key-secret", index, secretIndex, secret, owner)
			}
		}
	}
	return validateModelAccess(config)
}

func validateContainer(index int, container *Container, availableGPUs int, volumes map[string]bool, options Options) error {
	lists := []struct {
		name  string
		count int
	}{
		{"command", len(container.Command)}, {"entrypoint", len(container.Entrypoint)}, {"env", len(container.Env)},
		{"secrets", len(container.Secrets)}, {"models", len(container.Models)}, {"volumes", len(container.Volumes)}, {"devices", len(container.Devices)},
		{"keys", len(container.Keys)},
		{"cap_add", len(container.CapAdd)}, {"networks", len(container.Networks)},
		{"ports", len(container.Ports)},
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
	if err := validateContainerImage(index, container.Image); err != nil {
		return err
	}
	if err := validateContainerPolicy(index, container, availableGPUs, volumes, options); err != nil {
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

func validateModelAccess(config *Config) error {
	grants := make(map[string]int, len(config.Models))
	for containerIndex, container := range config.Containers {
		seen := map[string]bool{}
		for modelIndex, name := range container.Models {
			if !modelNamePattern.MatchString(name) {
				return fmt.Errorf("containers[%d].models[%d] %q is invalid", containerIndex, modelIndex, name)
			}
			if seen[name] {
				return fmt.Errorf("containers[%d].models[%d] %q is duplicated", containerIndex, modelIndex, name)
			}
			seen[name] = true
			grants[name]++
		}
	}

	models := make(map[string]int, len(config.Models))
	requiredNames := make(map[string]bool, len(config.Models))
	for index, model := range config.Models {
		requiresName := model.EMWP != "" || grants[model.Name] != 0
		if requiresName && !modelNamePattern.MatchString(model.Name) {
			return fmt.Errorf("models[%d].name %q is invalid", index, model.Name)
		}
		if model.Name == "" {
			continue
		}
		if prior, found := models[model.Name]; found {
			if requiresName || requiredNames[model.Name] {
				return fmt.Errorf("models[%d].name %q duplicates models[%d].name", index, model.Name, prior)
			}
		} else {
			models[model.Name] = index
		}
		if requiresName {
			requiredNames[model.Name] = true
		}
	}
	for containerIndex, container := range config.Containers {
		for modelIndex, name := range container.Models {
			if _, found := models[name]; !found {
				return fmt.Errorf("containers[%d].models[%d] %q is not declared", containerIndex, modelIndex, name)
			}
		}
	}
	for index, model := range config.Models {
		if model.EMWP != "" && grants[model.Name] == 0 {
			return fmt.Errorf("models[%d] %q is encrypted and requires an explicit container grant", index, model.Name)
		}
	}
	return nil
}

func ModelIsIsolated(config *Config, name string) bool {
	for _, container := range config.Containers {
		if slices.Contains(container.Models, name) {
			return true
		}
	}
	return false
}

func validateContainerImage(index int, image string) error {
	if image == "" {
		return fmt.Errorf("containers[%d].image is required", index)
	}
	named, err := reference.ParseNormalizedNamed(image)
	if err != nil {
		return fmt.Errorf("containers[%d].image %q is invalid: %w", index, image, err)
	}
	if _, ok := named.(reference.Digested); !ok {
		return fmt.Errorf("containers[%d].image %q must include an immutable digest", index, image)
	}
	return nil
}

func validateContainerPolicy(index int, container *Container, availableGPUs int, volumes map[string]bool, options Options) error {
	if container.CVMAdmin {
		if !slices.Contains([]string{"", "0", "0:0", "root", "root:root"}, container.User) {
			return fmt.Errorf("containers[%d].cvm_admin requires root user", index)
		}
	}
	if container.SealRegister {
		uid, _, _ := strings.Cut(container.User, ":")
		if _, err := strconv.ParseUint(uid, 10, 32); err != nil {
			return fmt.Errorf("containers[%d].seal_register requires a numeric uid in user", index)
		}
	}
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
		if ReservedDebugRuntimeEnabled(container.Name, options) && (volume == debugDockerSocketBind || volume == debugManagerSocketBind) {
			continue
		}
		source, target, found := strings.Cut(volume, ":")
		if !found || !volumes[source] {
			return fmt.Errorf("containers[%d].volumes[%d] must name a volume declared in volumes", index, volumeIndex)
		}
		if !path.IsAbs(target) || path.Clean(target) != target {
			return fmt.Errorf("containers[%d].volumes[%d] must mount at a clean absolute path", index, volumeIndex)
		}
	}
	for capabilityIndex, capability := range container.CapAdd {
		if !slices.Contains([]string{"IPC_LOCK", "NET_BIND_SERVICE", "SYS_NICE"}, capability) {
			return fmt.Errorf("containers[%d].cap_add[%d] capability %q is unsupported", index, capabilityIndex, capability)
		}
	}
	return nil
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
	publishedBy := map[int]string{}
	for index, container := range config.Containers {
		if err := validateContainerPorts(index, &container, publishedBy); err != nil {
			return err
		}
		seen := map[string]bool{}
		egressCount := 0
		for _, name := range container.Networks {
			if seen[name] {
				return fmt.Errorf("containers[%d] %q: network %q listed twice", index, container.Name, name)
			}
			seen[name] = true
			if name == reservedShimNetworkName {
				return fmt.Errorf("containers[%d] %q: %q is reserved", index, container.Name, reservedShimNetworkName)
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

// validateContainerPorts checks a container's `ports:` entries against the
// ports the CVM reserves for itself and against every other container's
// published ports, recording each claim in publishedBy.
func validateContainerPorts(index int, container *Container, publishedBy map[int]string) error {
	mappings, err := ParsePorts(container.Ports)
	if err != nil {
		return fmt.Errorf("containers[%d] %q: %v", index, container.Name, err)
	}
	if len(mappings) == 0 {
		return nil
	}
	if len(container.Networks) == 0 {
		return fmt.Errorf("containers[%d] %q: ports requires an attached network", index, container.Name)
	}
	for _, mapping := range mappings {
		if reserved, used := reservedHostPorts[mapping.Host]; used {
			return fmt.Errorf("containers[%d] %q: host port %d is reserved for %s", index, container.Name, mapping.Host, reserved)
		}
		if prior, taken := publishedBy[mapping.Host]; taken {
			return fmt.Errorf("containers[%d] %q: host port %d is already published by %q", index, container.Name, mapping.Host, prior)
		}
		publishedBy[mapping.Host] = container.Name
	}
	return nil
}

func validateNetworkEntry(name string, spec *NetworkSpec) error {
	if name == "" {
		return fmt.Errorf("empty network name")
	}
	if name == reservedShimNetworkName {
		return fmt.Errorf("name %q is reserved", reservedShimNetworkName)
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
	for index := 0; index < len(name); index++ {
		character := name[index]
		if character == '_' || character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' || index > 0 && character >= '0' && character <= '9' {
			continue
		}
		return false
	}
	return true
}

func validateCVMSource(source *CVMSource) error {
	if source == nil {
		return nil
	}
	if !cvmSourceRepoPattern.MatchString(source.Repo) {
		return fmt.Errorf("cvm-source repo %q must be a GitHub owner/name", source.Repo)
	}
	artifacts, err := url.Parse(source.Artifacts)
	if err != nil || artifacts.Scheme != "https" || artifacts.Host == "" || artifacts.RawQuery != "" || artifacts.Fragment != "" {
		return fmt.Errorf("cvm-source artifacts %q must be an https URL without query or fragment", source.Artifacts)
	}
	return nil
}
