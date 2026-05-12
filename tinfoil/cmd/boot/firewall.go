package main

import (
	"fmt"
	"log"
	"math"
	"os/exec"
)

// setupContainerNetworkFirewall adds forward rules for the container-net bridge.
// Must be called after the bridge interface exists so iif/oif resolve by index.
func setupContainerNetworkFirewall() error {
	privateRanges := "{ 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 127.0.0.0/8 }"
	rules := [][]string{
		// Allow return traffic into containers for connections they initiated.
		{"add", "rule", "inet", "tinfoil", "forward",
			"oif", containerBridgeName, "ct", "state", "established,related", "accept"},
		// Allow containers to initiate outbound connections to public IPs only;
		// drops traffic destined for RFC 1918 / link-local ranges to prevent
		// containers from reaching other VMs or host-internal services.
		{"add", "rule", "inet", "tinfoil", "forward",
			"iif", containerBridgeName, "oif", "!=", containerBridgeName,
			"ip", "daddr", "!=", privateRanges, "accept"},
		// Block container-net from initiating connections to the host via the
		// container-net gateway IP. We insert it at the top of the input chain
		// for priority.
		{"insert", "rule", "inet", "tinfoil", "input",
			"iif", containerBridgeName, "drop"},
	}
	for _, args := range rules {
		out, err := exec.Command("nft", args...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("nft add rule: %w (%s)", err, out)
		}
	}
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
