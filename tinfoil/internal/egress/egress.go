package egress

import (
	"context"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	"tinfoil/internal/boot"
	"tinfoil/internal/containernet"
	"tinfoil/internal/firewall"

	"gopkg.in/yaml.v3"
)

const refreshInterval = 60 * time.Second

type config struct {
	Networks map[string]network `yaml:"networks"`
}

type network struct {
	Allow []string `yaml:"allow"`
}

type nftClient struct {
	apply func(string) ([]byte, error)
}

// Engine maintains the nft allow sets described by the boot-generated config.
type Engine struct {
	config   *config
	resolve  func(context.Context, []string) ([]string, error)
	nft      nftClient
	interval time.Duration
}

// Load reads the boot-generated config and previous resolved-address state.
func Load() (*Engine, error) {
	cfg, err := loadConfig(boot.EgressConfigPath)
	if err != nil {
		return nil, err
	}
	return &Engine{
		config:  cfg,
		resolve: resolve,
		nft: nftClient{
			apply: applyDelta,
		},
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

// Refresh resolves every allowlist, then replaces all fixed sets in one nft
// transaction. No runtime state file or parser is needed.
func (e *Engine) Refresh(ctx context.Context) error {
	names := make([]string, 0, len(e.config.Networks))
	resolved := make(map[string][]string, len(e.config.Networks))
	for name := range e.config.Networks {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		current, err := e.resolve(ctx, e.config.Networks[name].Allow)
		if err != nil {
			return fmt.Errorf("network %q: %w", name, err)
		}
		resolved[name] = current
	}
	if len(names) == 0 {
		return nil
	}
	var script strings.Builder
	for _, name := range names {
		setName := containernet.AllowSetPrefix + name
		fmt.Fprintf(&script, "flush set inet tinfoil %s\n", setName)
		if len(resolved[name]) > 0 {
			fmt.Fprintf(&script, "add element inet tinfoil %s { %s }\n",
				setName, strings.Join(resolved[name], ", "))
		}
	}
	if out, err := e.nft.apply(script.String()); err != nil {
		return fmt.Errorf("replacing egress allow sets: %w (%s)", err, out)
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

func applyDelta(script string) ([]byte, error) {
	return firewall.ApplyOutput(script)
}
