package firewall

import (
	"fmt"
	"log"
	"sort"
	"strings"

	"tinfoil/internal/containernet"
	"tinfoil/internal/runtimeconfig"
)

const (
	nonPublicIPv4Ranges = "{ 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.0.2.0/24, 192.168.0.0/16, 198.18.0.0/15, 198.51.100.0/24, 203.0.113.0/24, 224.0.0.0/4, 240.0.0.0/4, 255.255.255.255/32 }"
	nonPublicIPv6Ranges = "{ fc00::/7, fe80::/10, ff00::/8, ::ffff:0:0/96, 64:ff9b::/96, 100::/64, 2001:db8::/32, ::1/128 }"
)

func ApplyContainerNetworks(config *runtimeconfig.Config, debug bool) error {
	script, err := renderContainerNetworkScript(config, debug)
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

func renderContainerNetworkScript(config *runtimeconfig.Config, debug bool) (string, error) {
	names := make([]string, 0, len(config.Networks))
	for name := range config.Networks {
		names = append(names, name)
	}
	sort.Strings(names)
	published, err := publishedPortsByBridge(config)
	if err != nil {
		return "", err
	}
	var script strings.Builder
	script.WriteString("flush chain inet tinfoil container_input\n")
	script.WriteString("flush chain inet tinfoil container_forward\n")
	for _, name := range names {
		// Published-port rules go first: on an `open` or `allowlist` bridge
		// the egress policy drops traffic addressed to private ranges, which
		// would otherwise eat the reply leg of a connection opened from one.
		writePublishedPortRules(&script, name, published[name])
		writeBridgeRules(&script, name, config.Networks[name])
	}
	if runtimeconfig.ShimUpstreamSet(config) {
		writeBridgeRules(&script, containernet.ShimNetName, &runtimeconfig.NetworkSpec{Egress: "closed"})
	}
	if debug && runtimeconfig.HasReservedDebugContainer(config) {
		// The toolbox publishes onto docker0, which is not a declared
		// network and so gets no writeBridgeRules pass of its own.
		writePublishedPortRules(&script, "docker0", []int{runtimeconfig.ReservedDebugHostPort})
	}
	return script.String(), nil
}

// publishedPortsByBridge groups every container's published container-side
// ports under the bridge Docker DNATs them on — the container's first
// attached network, the same one it is created with.
func publishedPortsByBridge(config *runtimeconfig.Config) (map[string][]int, error) {
	published := map[string][]int{}
	for _, container := range config.Containers {
		ports, err := runtimeconfig.ParsePorts(container.Ports)
		if err != nil {
			return nil, fmt.Errorf("container %s: %v", container.Name, err)
		}
		if len(ports) == 0 {
			continue
		}
		bridge, _ := runtimeconfig.AttachOrder(container, config)
		if bridge == "" {
			continue
		}
		for _, mapping := range ports {
			published[bridge] = append(published[bridge], mapping.Container)
		}
	}
	for _, ports := range published {
		sort.Ints(ports)
	}
	return published, nil
}

// writePublishedPortRules opens the forward path for ports Docker DNATs into
// bridge: the inbound leg is matched after translation, so the rule carries
// the container-side port, and the reply leg needs its own accept because
// writeBridgeRules only covers container-initiated flows. Accepting an
// established flow out of the bridge cannot widen egress — a flow only
// becomes established once its first packet survived the policy below.
func writePublishedPortRules(script *strings.Builder, bridge string, ports []int) {
	if len(ports) == 0 {
		return
	}
	for _, port := range ports {
		fmt.Fprintf(script, "add rule inet tinfoil container_forward oifname %q ct status dnat tcp dport %d accept\n", bridge, port)
	}
	fmt.Fprintf(script, "add rule inet tinfoil container_forward iifname %q ct state established,related accept\n", bridge)
}

func writeBridgeRules(script *strings.Builder, bridge string, network *runtimeconfig.NetworkSpec) {
	fmt.Fprintf(script, "add rule inet tinfoil container_forward iifname %q oifname %q accept\n", bridge, bridge)
	fmt.Fprintf(script, "add rule inet tinfoil container_forward oifname %q ct state established,related accept\n", bridge)
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
		fmt.Fprintf(script, "create set inet tinfoil %s { type ipv4_addr; }\n", setName)
		fmt.Fprintf(script, "add rule inet tinfoil container_forward iifname %q ip daddr @%s accept\n", bridge, setName)
		fmt.Fprintf(script, "add rule inet tinfoil container_forward iifname %q ip daddr %s drop\n", bridge, nonPublicIPv4Ranges)
		fmt.Fprintf(script, "add rule inet tinfoil container_forward iifname %q ip6 daddr %s drop\n", bridge, nonPublicIPv6Ranges)
	case "closed":
	}
}
