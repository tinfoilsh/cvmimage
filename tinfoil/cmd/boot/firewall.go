package main

import (
	"fmt"
	"log"
	"math"
	"os/exec"
	"strings"
)

func setupFirewall(config *Config) error {
	ports := config.CVMNetwork.InboundPorts
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

func runNft(script string) error {
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nft -f -: %w (%s)\nscript:\n%s", err, out, script)
	}
	return nil
}
