package main

import (
	"fmt"
	"net"
	"regexp"
	"slices"
	"strings"

	"tinfoil/internal/containernet"
)

var rfc1123HostnamePattern = regexp.MustCompile(
	`^(?i)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`,
)

const (
	maxHostnameLength = 253
	maxBridgeNameLen = 15
)

var validEgressModes = []string{"closed", "allowlist", "open"}

var networkNamePattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)

func validateNetwork(cfg *Config) error {
	for _, port := range cfg.CVMNetwork.InboundPorts {
		if port < 1 || port > 65535 {
			return fmt.Errorf("cvm-network.inbound-ports: %d is not in 1..65535", port)
		}
	}

	// Materialize nil entries (from `name:` with no body) as default-closed.
	for name, spec := range cfg.Networks {
		if spec == nil {
			cfg.Networks[name] = &NetworkSpec{Egress: "closed"}
		}
	}

	for name, spec := range cfg.Networks {
		if err := validateNetworkEntry(name, spec); err != nil {
			return fmt.Errorf("networks.%s: %w", name, err)
		}
	}

	for i, c := range cfg.Containers {
		seen := map[string]bool{}
		egressCount := 0
		for _, n := range c.Networks {
			if seen[n] {
				return fmt.Errorf("containers[%d] %q: network %q listed twice", i, c.Name, n)
			}
			seen[n] = true
			if n == containernet.ShimNetName {
				return fmt.Errorf("containers[%d] %q: %q is reserved", i, c.Name, containernet.ShimNetName)
			}
			spec, ok := cfg.Networks[n]
			if !ok {
				return fmt.Errorf("containers[%d] %q: network %q not declared", i, c.Name, n)
			}
			if spec.Egress != "closed" {
				egressCount++
			}
		}
		if egressCount > 1 {
			return fmt.Errorf("containers[%d] %q: at most one attached network may have egress != closed", i, c.Name)
		}
	}

	if cfg.ShimCfg != nil && cfg.ShimCfg.UpstreamContainer != "" {
		found := false
		for _, c := range cfg.Containers {
			if c.Name == cfg.ShimCfg.UpstreamContainer {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("shim.upstream-container %q does not match any containers[].name", cfg.ShimCfg.UpstreamContainer)
		}
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
	for i, host := range spec.Allow {
		if err := validateAllowEntry(host); err != nil {
			return fmt.Errorf("allow[%d] %q: %w", i, host, err)
		}
	}
	return nil
}

func validateAllowEntry(host string) error {
	if host == "" {
		return fmt.Errorf("empty entry")
	}
	if strings.Contains(host, "*") {
		return fmt.Errorf("wildcards are reserved for future tinfoil-dns support")
	}
	if ip := net.ParseIP(host); ip != nil {
		return fmt.Errorf("IP literals are not allowed; use a hostname")
	}
	if len(host) > maxHostnameLength {
		return fmt.Errorf("hostname exceeds %d-byte DNS limit", maxHostnameLength)
	}
	if !rfc1123HostnamePattern.MatchString(host) {
		return fmt.Errorf("not a valid DNS hostname")
	}
	return nil
}
