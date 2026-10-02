package firewall

import (
	"fmt"
	"log"
	"slices"
	"sort"
	"strings"

	"tinfoil/internal/containernet"
	"tinfoil/internal/runtimeconfig"
)

const (
	nonPublicIPv4Ranges = "{ 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.0.2.0/24, 192.168.0.0/16, 198.18.0.0/15, 198.51.100.0/24, 203.0.113.0/24, 224.0.0.0/4, 240.0.0.0/4, 255.255.255.255/32 }"
	nonPublicIPv6Ranges = "{ fc00::/7, fe80::/10, ff00::/8, ::ffff:0:0/96, 64:ff9b::/96, 100::/64, 2001:db8::/32, ::1/128 }"
)

func ApplyContainerNetworks(config *runtimeconfig.Config, debug bool, generation uint32) error {
	script, err := renderContainerNetworkScript(config, debug, generation)
	if err != nil {
		return err
	}
	if err := Apply(script); err != nil {
		return fmt.Errorf("installing container-network firewall rules: %w", err)
	}
	for name, network := range config.Networks {
		log.Printf("Firewall: network %q egress=%s", name, network.Egress)
	}
	if runtimeconfig.ShimUpstreamSet(config) {
		log.Printf("Firewall: network %q egress=closed (implicit shim channel)", containernet.ShimNetName)
	}
	return nil
}

func renderContainerNetworkScript(config *runtimeconfig.Config, debug bool, generation uint32) (string, error) {
	if generation == 0 || uint64(generation)+uint64(len(config.Networks)) > uint64(^uint32(0))+1 {
		return "", fmt.Errorf("invalid network policy generation")
	}
	adminSSH, err := runtimeconfig.AdminSSH(config, debug)
	if err != nil {
		return "", err
	}
	names := make([]string, 0, len(config.Networks))
	for name := range config.Networks {
		names = append(names, name)
	}
	sort.Strings(names)
	var script strings.Builder
	script.WriteString("flush chain inet tinfoil container_input\n")
	script.WriteString("flush chain inet tinfoil container_forward\n")
	if debug && runtimeconfig.HasReservedDebugContainer(config) {
		writeReservedDebugForwardRules(&script)
	}
	if adminSSH != nil {
		for _, container := range config.Containers {
			if container.Name != adminSSH.Container {
				continue
			}
			bridges := container.Networks
			if runtimeconfig.ShimUpstreamSet(config) && container.Name == config.ShimCfg.UpstreamContainer {
				bridges = slices.Concat(bridges, []string{containernet.ShimNetName})
			}
			for _, bridge := range bridges {
				fmt.Fprintf(&script, "add rule inet tinfoil container_forward oifname %q ct status dnat ct original proto-dst %d tcp dport %d accept\n", bridge, adminSSH.GuestPort, adminSSH.ContainerPort)
				fmt.Fprintf(&script, "add rule inet tinfoil container_forward iifname %q ct status dnat ct direction reply ct original proto-dst %d ct state established,related accept\n", bridge, adminSSH.GuestPort)
			}
		}
	}
	// Every other published port is reachable only over the shim's CONNECT tunnel.
	script.WriteString("add rule inet tinfoil container_forward ct status dnat drop\n")
	for i, name := range names {
		writeBridgeRules(&script, name, config.Networks[name], generation+uint32(i))
	}
	if runtimeconfig.ShimUpstreamSet(config) {
		writeBridgeRules(&script, containernet.ShimNetName, &runtimeconfig.NetworkSpec{Egress: "closed"}, generation)
	}
	return script.String(), nil
}

func writeReservedDebugForwardRules(script *strings.Builder) {
	fmt.Fprintf(script, "add rule inet tinfoil container_forward oifname %q ct status dnat tcp dport %d accept\n", "docker0", runtimeconfig.ReservedDebugHostPort)
	fmt.Fprintf(script, "add rule inet tinfoil container_forward iifname %q ct state established,related accept\n", "docker0")
}

func writeBridgeRules(script *strings.Builder, bridge string, network *runtimeconfig.NetworkSpec, generation uint32) {
	fmt.Fprintf(script, "add rule inet tinfoil container_forward iifname %q oifname %q accept\n", bridge, bridge)
	if network.Egress == "allowlist" {
		fmt.Fprintf(script, "add rule inet tinfoil container_forward oifname %q ct state established,related ct mark %d accept\n", bridge, generation)
	} else {
		fmt.Fprintf(script, "add rule inet tinfoil container_forward oifname %q ct state established,related accept\n", bridge)
	}
	fmt.Fprintf(script, "add rule inet tinfoil container_input iifname %q ip daddr %s meta l4proto { tcp, udp } th dport 53 accept\n", bridge, containernet.DNSAddress)
	fmt.Fprintf(script, "add rule inet tinfoil container_input iifname %q ct state new drop\n", bridge)
	switch network.Egress {
	case "open":
		fmt.Fprintf(script, "add rule inet tinfoil container_forward iifname %q ip daddr %s drop\n", bridge, nonPublicIPv4Ranges)
		fmt.Fprintf(script, "add rule inet tinfoil container_forward iifname %q meta nfproto ipv4 accept\n", bridge)
		fmt.Fprintf(script, "add rule inet tinfoil container_forward iifname %q ip6 daddr %s drop\n", bridge, nonPublicIPv6Ranges)
		fmt.Fprintf(script, "add rule inet tinfoil container_forward iifname %q meta nfproto ipv6 accept\n", bridge)
	case "allowlist":
		setName := containernet.AllowSetPrefix + bridge
		fmt.Fprintf(script, "destroy set inet tinfoil %s\n", setName)
		fmt.Fprintf(script, "create set inet tinfoil %s { type ipv4_addr; flags timeout; size %d; }\n", setName, containernet.MaxDNSAddresses)
		fmt.Fprintf(script, "add rule inet tinfoil container_forward iifname %q meta l4proto { tcp, udp } th dport { 53, 853 } drop\n", bridge)
		fmt.Fprintf(script, "add rule inet tinfoil container_forward iifname %q ip daddr %s drop\n", bridge, nonPublicIPv4Ranges)
		fmt.Fprintf(script, "add rule inet tinfoil container_forward iifname %q meta nfproto ipv4 ct state established,related ct mark %d accept\n", bridge, generation)
		fmt.Fprintf(script, "add rule inet tinfoil container_forward iifname %q ip daddr @%s ct mark set %d accept\n", bridge, setName, generation)
		fmt.Fprintf(script, "add rule inet tinfoil container_forward iifname %q ip6 daddr %s drop\n", bridge, nonPublicIPv6Ranges)
	case "closed":
	}
}
