package main

import (
	"fmt"
	"log"
	"math"
	"os/exec"
)

// setupContainerNetworkFirewall adds forward rules for the container-net bridge.
// Must be called after the bridge interface exists so iif/oif resolve by index.
// When trustedDomains is non-empty, an empty named set is created and the forward
// rules reference it; tinfoil-egress.service is started to perform the initial
// DNS resolution and populate the set. The associated timer then refreshes the
// set every 60 seconds. When trustedDomains is empty, all public destinations
// are allowed.
func setupContainerNetworkFirewall(trustedDomains []string) error {
	privateRanges := "{ 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 127.0.0.0/8 }"

	// Allow return traffic into containers for connections they initiated.
	out, err := exec.Command("nft", "add", "rule", "inet", "tinfoil", "forward",
		"oif", containerBridgeName, "ct", "state", "established,related", "accept").CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft add return-traffic rule: %w (%s)", err, out)
	}

	// Block container-net from initiating connections to the host via the
	// container-net gateway IP. We insert it at the top of the input chain
	// for priority.
	out, err = exec.Command("nft", "insert", "rule", "inet", "tinfoil", "input",
		"iif", containerBridgeName, "drop").CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft add block container->host rule: %w (%s)", err, out)
	}

	// No allowlist: permit containers to reach all public IPs.
	if len(trustedDomains) == 0 {
		// Drops traffic destined for RFC 1918 / link-local to prevent containers
		// from reaching other VMs or host-internal services.
		out, err := exec.Command("nft", "add", "rule", "inet", "tinfoil", "forward",
			"iif", containerBridgeName,
			"ip", "daddr", "!=", privateRanges, "accept").CombinedOutput()
		if err != nil {
			return fmt.Errorf("nft add forward rule: %w (%s)", err, out)
		}
		return nil
	}

	// Trusted-domains mode: create an empty set; tinfoil-egress populates it.
	exec.Command("nft", "add", "set", "inet", "tinfoil", "container-outgoing-allow",
		"{ type ipv4_addr; }").Run()

	// Drop RFC 1918 / link-local explicitly before the allowlist.
	out, err = exec.Command("nft", "add", "rule", "inet", "tinfoil", "forward",
		"iif", containerBridgeName,
		"ip", "daddr", privateRanges, "drop").CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft add drop-private rule: %w (%s)", err, out)
	}

	// Allow only trusted IPs; chain policy drops everything else.
	out, err = exec.Command("nft", "add", "rule", "inet", "tinfoil", "forward",
		"iif", containerBridgeName,
		"ip", "daddr", "@container-outgoing-allow", "accept").CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft add allow-trusted rule: %w (%s)", err, out)
	}

	// Start the service synchronously for the initial population. systemctl start
	// blocks until the oneshot exits, so any resolution or nftables failure here
	// surfaces as a boot error.
	log.Println("Firewall: starting tinfoil-egress for initial IP population")
	if out, err = exec.Command("systemctl", "start",
		"tinfoil-egress.service").CombinedOutput(); err != nil {
		return fmt.Errorf("tinfoil-egress.service failed on initial run: %w (%s)", err, out)
	}
	log.Println("Firewall: trusted-domains mode active, IP allowlist populated")

	return nil
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
