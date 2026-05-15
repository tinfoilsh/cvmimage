package main

import (
	"fmt"
	"log"
	"math"
	"os/exec"
	"strings"

	"tinfoil/internal/containernet"
)

// setupContainerNetworkFirewall adds forward rules for the container-net bridge.
// Must be called after the bridge interface exists so iif/oif resolve by index.
// trustedDomains and trustAllDomains are validated for exclusivity by the caller.
func setupContainerNetworkFirewall(trustedDomains []string, trustAllDomains bool) error {
	privateIPv4Ranges := "{ 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 127.0.0.0/8 }"
	privateIPv6Ranges := "{ fc00::/7, fe80::/10, ff00::/8, ::ffff:0:0/96, 64:ff9b::/96, 100::/64, 2001:db8::/32, ::1/128 }"

	var script strings.Builder

	// Allow container ↔ container traffic. Only fires when br_netfilter is
	// loaded with bridge-nf-call-iptables=1, in which case bridged frames
	// also traverse this L3 forward hook and would otherwise be dropped
	// (both endpoints sit in the bridge's RFC1918 subnet).
	fmt.Fprintf(&script, "add rule inet tinfoil forward iif %q oif %q accept\n",
		containernet.BridgeName, containernet.BridgeName)

	// Allow return traffic into containers for connections they initiated.
	fmt.Fprintf(&script, "add rule inet tinfoil forward oif %q ct state established,related accept\n",
		containernet.BridgeName)

	// Block new connections from container-net to the host (the shim's :443,
	// admin endpoints, etc.). Inserted first so it fires before the static
	// `tcp dport 443 accept`. Scoped to `ct state new` so reply traffic on
	// host→container connections (the shim's responses from the upstream)
	// still matches the static `ct state established,related accept` rule.
	fmt.Fprintf(&script, "insert rule inet tinfoil input iif %q ct state new drop\n",
		containernet.BridgeName)

	switch {
	case trustAllDomains:
		// One rule per address family: nft rejects multiple verdicts in a
		// single rule (`accept` is terminal).
		fmt.Fprintf(&script, "add rule inet tinfoil forward iif %q ip daddr != %s accept\n",
			containernet.BridgeName, privateIPv4Ranges)
		fmt.Fprintf(&script, "add rule inet tinfoil forward iif %q ip6 daddr != %s accept\n",
			containernet.BridgeName, privateIPv6Ranges)

	case len(trustedDomains) > 0:
		fmt.Fprintf(&script, "add set inet tinfoil container-outgoing-allow { type ipv4_addr; }\n")
		fmt.Fprintf(&script, "add rule inet tinfoil forward iif %q ip daddr %s drop\n",
			containernet.BridgeName, privateIPv4Ranges)
		fmt.Fprintf(&script, "add rule inet tinfoil forward iif %q ip6 daddr %s drop\n",
			containernet.BridgeName, privateIPv6Ranges)
		// Allow only trusted IPs; chain policy drops everything else.
		fmt.Fprintf(&script, "add rule inet tinfoil forward iif %q ip daddr @container-outgoing-allow accept\n",
			containernet.BridgeName)
	}

	if err := runNft(script.String()); err != nil {
		return fmt.Errorf("installing container-net firewall rules: %w", err)
	}

	switch {
	case trustAllDomains:
		log.Println("Firewall: trust-all-domains active, unrestricted public egress permitted")
	case len(trustedDomains) > 0:
		// Start the service synchronously for the initial population. systemctl
		// start blocks until the oneshot exits, so any resolution or nftables
		// failure here surfaces as a boot error.
		log.Println("Firewall: starting tinfoil-egress for initial IP population")
		if out, err := exec.Command("systemctl", "start",
			"tinfoil-egress.service").CombinedOutput(); err != nil {
			return fmt.Errorf("tinfoil-egress.service failed on initial run: %w (%s)", err, out)
		}
		log.Println("Firewall: trusted-domains mode active, IP allowlist populated")
	default:
		log.Println("Firewall: deny-by-default active, no public egress permitted")
	}

	return nil
}

// setupFirewall opens additional inbound ports beyond the shim's listen-port
// (which is already allowed by the static nftables.conf baked into the image).
func setupFirewall(config *Config) error {
	ports := config.Network.AllowedInboundPorts
	if len(ports) == 0 {
		log.Println("No additional inbound ports to open")
		return nil
	}

	var script strings.Builder
	for _, port := range ports {
		if port < 1 || port > math.MaxUint16 {
			return fmt.Errorf("invalid port number: %d", port)
		}
		log.Printf("Opening inbound port %d", port)
		fmt.Fprintf(&script, "add rule inet tinfoil input tcp dport %d accept\n", port)
	}

	if err := runNft(script.String()); err != nil {
		return fmt.Errorf("opening inbound ports %v: %w", ports, err)
	}

	log.Printf("Firewall: allowed inbound ports %v (in addition to shim port)", ports)
	return nil
}

// runNft pipes script to `nft -f -` so it commits as one netlink transaction.
func runNft(script string) error {
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nft -f -: %w (%s)\nscript:\n%s", err, out, script)
	}
	return nil
}
