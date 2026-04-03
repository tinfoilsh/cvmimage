package main

import (
	"fmt"
	"log"
	"math"
	"os/exec"
)

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
