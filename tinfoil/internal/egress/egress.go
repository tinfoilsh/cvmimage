package egress

import (
	"context"
	"fmt"
	"net"
	"net/netip"
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

// Load reads the boot-generated allowlist config.
func Load() (*Engine, error) {
	cfg, err := loadConfig(boot.EgressConfigPath)
	if err != nil {
		return nil, err
	}
	return &Engine{
		config:  cfg,
		resolve: resolve,
		nft: nftClient{
			apply: firewall.ApplyOutput,
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
		for _, value := range addrs {
			addr, err := netip.ParseAddr(value)
			if err != nil || !publicIPv4(addr) {
				continue
			}
			canonical := addr.String()
			if !seen[canonical] {
				seen[canonical] = true
				ips = append(ips, canonical)
			}
		}
	}
	if len(ips) == 0 && len(domains) > 0 {
		return nil, fmt.Errorf("no IPv4 addresses resolved for %v", domains)
	}
	return ips, nil
}

func publicIPv4(addr netip.Addr) bool {
	if !addr.Is4() {
		return false
	}
	for _, prefix := range nonPublicIPv4Prefixes {
		if prefix.Contains(addr) {
			return false
		}
	}
	return true
}

var nonPublicIPv4Prefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"), netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"), netip.MustParsePrefix("240.0.0.0/4"),
}
