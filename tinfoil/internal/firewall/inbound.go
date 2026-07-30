package firewall

import (
	"fmt"
	"log"
	"math"
	"strings"
)

func ApplyInbound(ports []int) error {
	script, err := renderInboundScript(ports)
	if err != nil {
		return err
	}
	if err := Apply(script); err != nil {
		return fmt.Errorf("applying inbound ports %v: %w", ports, err)
	}
	log.Printf("Firewall: allowed inbound ports %v (in addition to shim port)", ports)
	return nil
}

func renderInboundScript(ports []int) (string, error) {
	var script strings.Builder
	script.WriteString("flush chain inet tinfoil inbound\n")
	for _, port := range ports {
		if port < 1 || port > math.MaxUint16 {
			return "", fmt.Errorf("invalid port number: %d", port)
		}
		log.Printf("Opening inbound port %d", port)
		script.WriteString(inboundRule(port))
	}
	return script.String(), nil
}

func inboundRule(port int) string {
	return fmt.Sprintf("add rule inet tinfoil inbound tcp dport %d accept\n", port)
}
