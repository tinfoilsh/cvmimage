package main

import (
	"fmt"
	"log"
	"math"
	"os/exec"
	"sort"
	"strings"

	"tinfoil/internal/boot"
	"tinfoil/internal/containernet"
)

// Non-public destination ranges blocked even on `egress: open` and
// `egress: allowlist` networks. This keeps broad/public egress from reaching
// host/provider/internal address space while preserving same-bridge IPC, which
// is accepted before these routed-egress rules.
//
// References:
//   - RFC 1918: private-use networks.
//   - RFC 3927: IPv4 link-local.
//   - RFC 5737: documentation/test networks.
//   - RFC 6598: shared address space for carrier-grade NAT.
//   - RFC 6890 / IANA IPv4 Special-Purpose Address Registry: loopback,
//     "this network", benchmarking, multicast, reserved, and broadcast space.
const (
	nonPublicIPv4Ranges = "{ 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.2.0/24, 192.168.0.0/16, 198.18.0.0/15, 198.51.100.0/24, 203.0.113.0/24, 224.0.0.0/4, 240.0.0.0/4, 255.255.255.255/32 }"
	nonPublicIPv6Ranges = "{ fc00::/7, fe80::/10, ff00::/8, ::ffff:0:0/96, 64:ff9b::/96, 100::/64, 2001:db8::/32, ::1/128 }"
)

// setupContainerNetworkFirewall installs one bridge's worth of nftables
// rules per declared network plus the implicit shim-net, in a single
// transaction, then starts tinfoil-egress if any network needs it.
// Must be called after the bridge interfaces exist so iif/oif resolve
// by index.
func setupContainerNetworkFirewall(cfg *Config) error {
	names := make([]string, 0, len(cfg.Networks))
	for k := range cfg.Networks {
		names = append(names, k)
	}
	sort.Strings(names)

	var script strings.Builder
	for _, name := range names {
		writeBridgeRules(&script, name, cfg.Networks[name])
	}
	if shimUpstreamSet(cfg) {
		writeBridgeRules(&script, containernet.ShimNetName, &NetworkSpec{Egress: "closed"})
	}
	if err := runNft(script.String()); err != nil {
		return fmt.Errorf("installing container-network firewall rules: %w", err)
	}

	for _, name := range names {
		log.Printf("Firewall: network %q egress=%s", name, cfg.Networks[name].Egress)
	}
	if shimUpstreamSet(cfg) {
		log.Printf("Firewall: network %q egress=closed (implicit shim channel)", containernet.ShimNetName)
	}

	for _, spec := range cfg.Networks {
		if spec.Egress != "allowlist" {
			continue
		}
		log.Println("Firewall: starting tinfoil-egress for initial IP population")
		cmd := exec.Command(boot.InitBinary, "--exec-service", boot.EgressServiceName, "--", boot.EgressBinary, "--once")
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("tinfoil-egress --once failed: %w (%s)", err, out)
		}
		break
	}
	return nil
}

func writeBridgeRules(script *strings.Builder, bridge string, spec *NetworkSpec) {
	// Allow container ↔ container traffic. Only fires when br_netfilter is
	// loaded with bridge-nf-call-iptables=1, in which case bridged frames
	// also traverse this L3 forward hook and would otherwise be dropped.
	fmt.Fprintf(script, "add rule inet tinfoil forward iif %q oif %q accept\n", bridge, bridge)

	// Allow return traffic into containers for connections they initiated.
	fmt.Fprintf(script, "add rule inet tinfoil forward oif %q ct state established,related accept\n", bridge)

	// Block new connections from the bridge to the host. Scoped to
	// `ct state new` so reply traffic on host→container connections
	// (e.g. the shim's responses) still matches the static
	// `ct state established,related accept` rule.
	fmt.Fprintf(script, "insert rule inet tinfoil input iif %q ct state new drop\n", bridge)

	switch spec.Egress {
	case "open":
		fmt.Fprintf(script, "add rule inet tinfoil forward iif %q ip daddr != %s accept\n",
			bridge, nonPublicIPv4Ranges)
		fmt.Fprintf(script, "add rule inet tinfoil forward iif %q ip6 daddr != %s accept\n",
			bridge, nonPublicIPv6Ranges)
	case "allowlist":
		setName := containernet.AllowSetPrefix + bridge
		fmt.Fprintf(script, "add set inet tinfoil %s { type ipv4_addr; }\n", setName)
		fmt.Fprintf(script, "add rule inet tinfoil forward iif %q ip daddr %s drop\n",
			bridge, nonPublicIPv4Ranges)
		fmt.Fprintf(script, "add rule inet tinfoil forward iif %q ip6 daddr %s drop\n",
			bridge, nonPublicIPv6Ranges)
		fmt.Fprintf(script, "add rule inet tinfoil forward iif %q ip daddr @%s accept\n",
			bridge, setName)
	}
}

func shimUpstreamSet(cfg *Config) bool {
	return cfg.ShimCfg != nil && cfg.ShimCfg.UpstreamContainer != ""
}

// setupFirewall opens additional inbound ports beyond the shim's listen-port
// (which is already allowed by the static nftables.conf baked into the image).
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

// runNft pipes script to `nft -f -` so it commits as one netlink transaction.
func runNft(script string) error {
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nft -f -: %w (%s)\nscript:\n%s", err, out, script)
	}
	return nil
}
