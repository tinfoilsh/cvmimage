package main

import (
	"context"
	"fmt"
	"log"
	"sort"
	"time"

	"tinfoil/internal/containernet"
	"tinfoil/internal/egress"
	"tinfoil/internal/netfilter"
)

const egressInitialPopulationTimeout = 30 * time.Second

type egressPopulator interface {
	Populate(context.Context) error
}

// setupContainerNetworkFirewall installs one bridge's worth of nftables
// rules per declared network plus the implicit shim-net, in a single
// transaction, then synchronously populates any allowlist sets.
// Must be called after the bridge interfaces exist so iif/oif resolve
// by index.
func setupContainerNetworkFirewall(ctx context.Context, cfg *Config, debug bool) error {
	return setupContainerNetworkFirewallWith(ctx, cfg, debug, netfilter.InstallNetworks, func() (egressPopulator, error) {
		return egress.Load()
	})
}

func setupContainerNetworkFirewallWith(
	ctx context.Context,
	cfg *Config,
	debug bool,
	install func(context.Context, []netfilter.Network, bool) error,
	loadEgress func() (egressPopulator, error),
) error {
	names := make([]string, 0, len(cfg.Networks))
	for k := range cfg.Networks {
		names = append(names, k)
	}
	sort.Strings(names)

	networks := make([]netfilter.Network, 0, len(names)+1)
	for _, name := range names {
		mode, err := netfilterMode(cfg.Networks[name].Egress)
		if err != nil {
			return fmt.Errorf("network %q: %w", name, err)
		}
		networks = append(networks, netfilter.Network{Name: name, Egress: mode})
	}
	if shimUpstreamSet(cfg) {
		networks = append(networks, netfilter.Network{Name: containernet.ShimNetName, Egress: netfilter.EgressClosed})
	}
	debugForward := debug && hasReservedDebugContainer(cfg)
	if err := install(ctx, networks, debugForward); err != nil {
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
		engine, err := loadEgress()
		if err != nil {
			return fmt.Errorf("loading egress policy: %w", err)
		}
		log.Println("Firewall: populating egress allowlists")
		populationCtx, cancel := context.WithTimeout(ctx, egressInitialPopulationTimeout)
		err = engine.Populate(populationCtx)
		cancel()
		if err != nil {
			return fmt.Errorf("populating egress allowlists: %w", err)
		}
		break
	}
	return nil
}

func netfilterMode(mode string) (netfilter.Egress, error) {
	switch mode {
	case "open":
		return netfilter.EgressOpen, nil
	case "allowlist":
		return netfilter.EgressAllowlist, nil
	case "closed":
		return netfilter.EgressClosed, nil
	default:
		return 0, fmt.Errorf("invalid egress mode %q", mode)
	}
}

func shimUpstreamSet(cfg *Config) bool {
	return cfg.ShimCfg != nil && cfg.ShimCfg.UpstreamContainer != ""
}

// setupFirewall opens additional inbound ports beyond the shim's listen-port
// (which is already allowed by the fixed measured ruleset installed by PID1).
func setupFirewall(ctx context.Context, config *Config) error {
	if len(config.CVMNetwork.InboundPorts) == 0 {
		log.Println("No additional inbound ports to open")
		return nil
	}

	ports := make([]uint16, len(config.CVMNetwork.InboundPorts))
	for index, port := range config.CVMNetwork.InboundPorts {
		if port < 1 || port > 65535 {
			return fmt.Errorf("invalid port number: %d", port)
		}
		log.Printf("Opening inbound port %d", port)
		ports[index] = uint16(port)
	}
	if err := netfilter.OpenInboundPorts(ctx, ports); err != nil {
		return fmt.Errorf("opening inbound ports %v: %w", ports, err)
	}

	log.Printf("Firewall: allowed inbound ports %v (in addition to shim port)", ports)
	return nil
}
