package main

import (
	"fmt"
	"log"
	"math"
	"os/exec"
)

// setupContainerNetworkFirewall adds forward rules for the container-net bridge.
// Must be called after the bridge interface exists so iif/oif resolve by index.
// trustedDomains and trustAllDomains are validated for exclusivity by the caller.
func setupContainerNetworkFirewall(trustedDomains []string, trustAllDomains bool) error {
	privateIPv4Ranges := "{ 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 127.0.0.0/8 }"
	privateIPv6Ranges := "{ fc00::/7, fe80::/10, ff00::/8, ::ffff:0:0/96, 64:ff9b::/96, 100::/64, 2001:db8::/32, ::1/128 }"

	// Allow container ↔ container traffic. Only fires when br_netfilter is
	// loaded with bridge-nf-call-iptables=1, in which case bridged frames
	// also traverse this L3 forward hook and would otherwise be dropped
	// (both endpoints sit in the bridge's RFC1918 subnet).
	out, err := exec.Command("nft", "add", "rule", "inet", "tinfoil", "forward",
		"iif", containerBridgeName, "oif", containerBridgeName, "accept").CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft add sibling-traffic rule: %w (%s)", err, out)
	}

	// Allow return traffic into containers for connections they initiated.
	out, err = exec.Command("nft", "add", "rule", "inet", "tinfoil", "forward",
		"oif", containerBridgeName, "ct", "state", "established,related", "accept").CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft add return-traffic rule: %w (%s)", err, out)
	}

	// Block new connections from container-net to the host (the shim's :443,
	// admin endpoints, etc.). Inserted first so it fires before the static
	// `tcp dport 443 accept`. Scoped to `ct state new` so reply traffic on
	// host→container connections (the shim's responses from the upstream)
	// still matches the static `ct state established,related accept` rule.
	out, err = exec.Command("nft", "insert", "rule", "inet", "tinfoil", "input",
		"iif", containerBridgeName, "ct", "state", "new", "drop").CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft add block container->host rule: %w (%s)", err, out)
	}

	switch {
	case trustAllDomains:
		// One rule per address family: nft rejects multiple verdicts in a
		// single rule (`accept` is terminal).
		out, err := exec.Command("nft", "add", "rule", "inet", "tinfoil", "forward",
			"iif", containerBridgeName, "ip", "daddr", "!=", privateIPv4Ranges, "accept").CombinedOutput()
		if err != nil {
			return fmt.Errorf("nft add forward v4 rule: %w (%s)", err, out)
		}
		out, err = exec.Command("nft", "add", "rule", "inet", "tinfoil", "forward",
			"iif", containerBridgeName, "ip6", "daddr", "!=", privateIPv6Ranges, "accept").CombinedOutput()
		if err != nil {
			return fmt.Errorf("nft add forward v6 rule: %w (%s)", err, out)
		}
		log.Println("Firewall: trust-all-domains active, unrestricted public egress permitted")
		return nil

	case len(trustedDomains) > 0:
		exec.Command("nft", "add", "set", "inet", "tinfoil", "container-outgoing-allow",
			"{ type ipv4_addr; }").Run()

		out, err := exec.Command("nft", "add", "rule", "inet", "tinfoil", "forward",
			"iif", containerBridgeName, "ip", "daddr", privateIPv4Ranges, "drop").CombinedOutput()
		if err != nil {
			return fmt.Errorf("nft add drop-private v4 rule: %w (%s)", err, out)
		}
		out, err = exec.Command("nft", "add", "rule", "inet", "tinfoil", "forward",
			"iif", containerBridgeName, "ip6", "daddr", privateIPv6Ranges, "drop").CombinedOutput()
		if err != nil {
			return fmt.Errorf("nft add drop-private v6 rule: %w (%s)", err, out)
		}

		// Allow only trusted IPs; chain policy drops everything else.
		out, err = exec.Command("nft", "add", "rule", "inet", "tinfoil", "forward",
			"iif", containerBridgeName,
			"ip", "daddr", "@container-outgoing-allow", "accept").CombinedOutput()
		if err != nil {
			return fmt.Errorf("nft add allow-trusted rule: %w (%s)", err, out)
		}

		// Start the service synchronously for the initial population. systemctl
		// start blocks until the oneshot exits, so any resolution or nftables
		// failure here surfaces as a boot error.
		log.Println("Firewall: starting tinfoil-egress for initial IP population")
		if out, err = exec.Command("systemctl", "start",
			"tinfoil-egress.service").CombinedOutput(); err != nil {
			return fmt.Errorf("tinfoil-egress.service failed on initial run: %w (%s)", err, out)
		}
		log.Println("Firewall: trusted-domains mode active, IP allowlist populated")
		return nil

	default:
		log.Println("Firewall: deny-by-default active, no public egress permitted")
		return nil
	}
}

// setupFirewall opens additional inbound ports beyond the shim's listen-port
// (which is already allowed by the static nftables.conf baked into the image).
// Each port is added as a new rule in the inet tinfoil input chain.
func setupFirewall(config *Config) error {
	ports := config.Network.AllowedInboundPorts
	if len(ports) == 0 {
		log.Println("No additional inbound ports to open")
		return nil
	}

	for _, port := range ports {
		if port < 1 || port > math.MaxUint16 {
			return fmt.Errorf("invalid port number: %d", port)
		}
		log.Printf("Opening inbound port %d", port)
		out, err := exec.Command("nft", "add", "rule", "inet", "tinfoil", "input",
			"tcp", "dport", fmt.Sprintf("%d", port), "accept").CombinedOutput()
		if err != nil {
			return fmt.Errorf("nft add rule for port %d: %w (%s)", port, err, out)
		}
	}

	log.Printf("Firewall: allowed inbound ports %v (in addition to shim port)", ports)
	return nil
}
