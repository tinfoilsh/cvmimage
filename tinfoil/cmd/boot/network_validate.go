package main

import (
	"fmt"
	"net"
	"regexp"
	"strings"
)

var rfc1123HostnamePattern = regexp.MustCompile(
	`^(?i)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`,
)

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
	return nil
}

func validateTrustedDomain(host string) error {
	if host == "" {
		return fmt.Errorf("empty entry")
	}
	if host == "*" {
		return fmt.Errorf(`bare "*" is not a hostname; use network.trust-all-domains: true`)
	}
	if strings.Contains(host, "*") {
		// Accept wildcard syntax so v0.9.0 configs forward-port; reject until
		// the in-enclave resolver that resolves them ships.
		return fmt.Errorf("wildcard hostnames are not yet supported; enumerate hosts explicitly")
	}
	if ip := net.ParseIP(host); ip != nil {
		return fmt.Errorf("IP literals are not allowed; use a hostname so tinfoil-egress can refresh it")
	}
	if !rfc1123HostnamePattern.MatchString(host) {
		return fmt.Errorf("not a valid DNS hostname")
	}
	return nil
}
