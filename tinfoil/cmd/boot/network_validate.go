package main

import (
	"fmt"
	"net"
	"regexp"
	"strings"
)

// rfc1123HostnamePattern matches a DNS hostname per RFC 1123. Labels are 1-63
// chars of [a-z0-9-] and may not start or end with a hyphen; the whole name is
// 1-253 chars. Case-insensitive intentionally — DNS is.
var rfc1123HostnamePattern = regexp.MustCompile(
	`^(?i)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`,
)

// validateNetwork enforces the v0.9.0 network schema. Called from
// loadAndVerifyConfig and loadConfigFromRamdisk so both parse paths reject the
// same configs.
func validateNetwork(cfg *Config) error {
	for i, c := range cfg.Containers {
		if c.NetworkMode != "" {
			return fmt.Errorf(
				"containers[%d] %q: network_mode is removed in v0.9.0; "+
					"see network.trusted-domains and network.trust-all-domains "+
					"for the supported egress controls",
				i, c.Name,
			)
		}
	}

	n := cfg.Network
	if n.TrustAllDomains && len(n.TrustedDomains) > 0 {
		return fmt.Errorf(
			"network.trust-all-domains: true and a non-empty network.trusted-domains " +
				"are mutually exclusive; pick one",
		)
	}

	for i, host := range n.TrustedDomains {
		if err := validateTrustedDomain(host); err != nil {
			return fmt.Errorf("network.trusted-domains[%d] %q: %w", i, host, err)
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
			return fmt.Errorf(
				"shim.upstream-container %q does not match any containers[].name",
				cfg.ShimCfg.UpstreamContainer,
			)
		}
	}
	return nil
}

// validateTrustedDomain rejects values that are not yet supported or that
// would silently mean something other than what they look like.
func validateTrustedDomain(host string) error {
	if host == "" {
		return fmt.Errorf("empty entry")
	}
	if host == "*" {
		return fmt.Errorf(
			"bare \"*\" is not a hostname; use network.trust-all-domains: true " +
				"for unrestricted public egress",
		)
	}
	if strings.Contains(host, "*") {
		// Anything else with a "*" is a wildcard form (*.foo.bar, foo.*.bar,
		// etc.). We accept the syntax — configs written today should keep
		// working when wildcards land — but refuse to act on it yet.
		return fmt.Errorf(
			"wildcard hostnames are not yet supported in v0.9.0; enumerate hosts " +
				"explicitly, wildcards will land in a future release",
		)
	}
	if ip := net.ParseIP(host); ip != nil {
		return fmt.Errorf(
			"IP literals are not allowed; use a hostname so tinfoil-egress can " +
				"refresh it",
		)
	}
	if !rfc1123HostnamePattern.MatchString(host) {
		return fmt.Errorf("not a valid DNS hostname")
	}
	return nil
}
