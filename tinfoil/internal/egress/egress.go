package egress

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sort"
	"time"

	"tinfoil/internal/boot"
	"tinfoil/internal/containernet"
	"tinfoil/internal/netfilter"

	"gopkg.in/yaml.v3"
)

const refreshInterval = 60 * time.Second

type config struct {
	Networks map[string]network `yaml:"networks"`
}

type network struct {
	Allow []string `yaml:"allow"`
}

// Engine maintains the fixed kernel allow sets described by the boot-generated config.
type Engine struct {
	config   *config
	resolve  func(context.Context, []string) ([]string, error)
	apply    func(context.Context, map[string][]netip.Addr) error
	interval time.Duration
}

// Load reads the boot-generated config and previous resolved-address state.
func Load() (*Engine, error) {
	cfg, err := loadConfig(boot.EgressConfigPath)
	if err != nil {
		return nil, err
	}
	return &Engine{
		config:   cfg,
		resolve:  resolve,
		apply:    netfilter.ReplaceAllowSets,
		interval: refreshInterval,
	}, nil
}

// Configured reports whether any allowlist networks need maintenance.
func (e *Engine) Configured() bool {
	return len(e.config.Networks) > 0
}

// Populate synchronously performs the initial allow-set population.
func (e *Engine) Populate(ctx context.Context) error {
	return e.Refresh(ctx)
}

// Refresh resolves every allowlist, then replaces all fixed sets in one netlink
// transaction. No runtime state file or parser is needed.
func (e *Engine) Refresh(ctx context.Context) error {
	names := make([]string, 0, len(e.config.Networks))
	resolved := make(map[string][]netip.Addr, len(e.config.Networks))
	for name := range e.config.Networks {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		current, err := e.resolve(ctx, e.config.Networks[name].Allow)
		if err != nil {
			return fmt.Errorf("network %q: %w", name, err)
		}
		addresses := make([]netip.Addr, len(current))
		for index, value := range current {
			address, err := netip.ParseAddr(value)
			if err != nil || !address.Is4() {
				return fmt.Errorf("network %q: resolver returned invalid IPv4 address %q", name, value)
			}
			addresses[index] = address
		}
		sort.Slice(addresses, func(i, j int) bool { return addresses[i].Compare(addresses[j]) < 0 })
		resolved[containernet.AllowSetPrefix+name] = addresses
	}
	if len(names) == 0 {
		return nil
	}
	if err := e.apply(ctx, resolved); err != nil {
		return fmt.Errorf("replacing egress allow sets: %w", err)
	}
	return nil
}

// Run refreshes at the daemon interval until ctx is canceled.
func (e *Engine) Run(ctx context.Context, refreshFailed func(error)) {
	ticker := time.NewTicker(e.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := e.Refresh(ctx); err != nil && refreshFailed != nil {
				refreshFailed(err)
			}
		}
	}
}

func loadConfig(path string) (*config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading egress config: %w", err)
	}
	var cfg config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing egress config: %w", err)
	}
	return &cfg, nil
}

func resolve(ctx context.Context, domains []string) ([]string, error) {
	seen := map[string]bool{}
	var ips []string
	for _, domain := range domains {
		addrs, err := net.DefaultResolver.LookupHost(ctx, domain)
		if err != nil {
			return nil, fmt.Errorf("resolving %s: %w", domain, err)
		}
		for _, addr := range addrs {
			if net.ParseIP(addr).To4() == nil {
				continue
			}
			if !seen[addr] {
				seen[addr] = true
				ips = append(ips, addr)
			}
		}
	}
	if len(ips) == 0 && len(domains) > 0 {
		return nil, fmt.Errorf("no IPv4 addresses resolved for %v", domains)
	}
	return ips, nil
}
