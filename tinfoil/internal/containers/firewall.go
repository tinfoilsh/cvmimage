package containers

import (
	"context"
	"fmt"
	"log"
	"time"

	"tinfoil/internal/egress"
	"tinfoil/internal/firewall"
)

const egressInitialPopulationTimeout = 30 * time.Second

type egressPopulator interface {
	Populate(context.Context) error
}

func setupContainerNetworkFirewall(ctx context.Context, config *Config, debug bool) error {
	return setupContainerNetworkFirewallWith(ctx, config, debug, firewall.ApplyContainerNetworks, func() (egressPopulator, error) {
		return egress.Load()
	})
}

func setupContainerNetworkFirewallWith(
	ctx context.Context,
	config *Config,
	debug bool,
	applyFirewall func(*Config, bool) error,
	loadEgress func() (egressPopulator, error),
) error {
	if err := applyFirewall(config, debug); err != nil {
		return err
	}
	for _, network := range config.Networks {
		if network.Egress != "allowlist" {
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
