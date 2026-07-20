package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"tinfoil/internal/boot"
	"tinfoil/internal/containernet"

	"gopkg.in/yaml.v3"
)

const refreshInterval = 60 * time.Second

func init() {
	log.SetFlags(0)
}

type egressConfig struct {
	Networks map[string]egressNetwork `yaml:"networks"`
}

type egressNetwork struct {
	Allow []string `yaml:"allow"`
}

func main() {
	once := len(os.Args) == 2 && os.Args[1] == "--once"
	if len(os.Args) > 1 && !once {
		log.Printf("usage: tinfoil-egress [--once]")
		os.Exit(2)
	}
	if err := run(once); err != nil {
		log.Printf("tinfoil-egress: %v", err)
		os.Exit(1)
	}
}

func run(once bool) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	if len(cfg.Networks) == 0 {
		log.Println("no allowlist networks configured, exiting")
		return nil
	}

	state := readState()

	// Initial population must succeed before the daemon enters its refresh
	// loop. tinfoil-boot runs `tinfoil-egress --once` through tinfoil-init's
	// hardening wrapper, so failures surface as boot errors.
	if err := refresh(cfg, state); err != nil {
		return fmt.Errorf("initial population: %w", err)
	}
	if once {
		return nil
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	ticker := time.NewTicker(refreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Println("shutting down")
			return nil
		case <-ticker.C:
			if err := refresh(cfg, state); err != nil {
				log.Printf("refresh failed: %v", err)
			}
		}
	}
}

func loadConfig() (*egressConfig, error) {
	data, err := os.ReadFile(boot.EgressConfigPath)
	if err != nil {
		return nil, fmt.Errorf("reading egress config: %w", err)
	}
	var cfg egressConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing egress config: %w", err)
	}
	return &cfg, nil
}

// refresh resolves each allowlist network's FQDNs and commits the
// per-set delta in one nft transaction. state is mutated in place.
func refresh(cfg *egressConfig, state map[string][]string) error {
	for name, net := range cfg.Networks {
		current, err := resolve(net.Allow)
		if err != nil {
			return fmt.Errorf("network %q: %w", name, err)
		}
		setName := containernet.AllowSetPrefix + name

		// Defensive: ensure the set exists. Normally created by tinfoil-boot.
		exec.Command("nft", "add", "set", "inet", "tinfoil", setName,
			"{ type ipv4_addr; }").Run()

		// Flushing and reloading could lead to a race condition where new outgoing
		// connections that should be allowed are not, so instead we calculate the
		// IPs to add and the set of IPs to remove from the set.
		prev := state[name]
		toAdd := difference(current, prev)
		toRemove := difference(prev, current)
		if len(toAdd) == 0 && len(toRemove) == 0 {
			continue
		}

		// Commit add+remove in one transaction so the set never appears with only
		// one half of the delta applied.
		var script strings.Builder
		if len(toAdd) > 0 {
			fmt.Fprintf(&script, "add element inet tinfoil %s { %s }\n",
				setName, strings.Join(toAdd, ", "))
		}
		if len(toRemove) > 0 {
			fmt.Fprintf(&script, "delete element inet tinfoil %s { %s }\n",
				setName, strings.Join(toRemove, ", "))
		}

		cmd := exec.Command("nft", "-f", "-")
		cmd.Stdin = strings.NewReader(script.String())
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("updating %s: %w (%s)", setName, err, out)
		}
		// Only record the new state after the kernel accepts the delta;
		state[name] = current
	}
	return writeState(state)
}

func resolve(domains []string) ([]string, error) {
	seen := map[string]bool{}
	var ips []string
	for _, domain := range domains {
		addrs, err := net.LookupHost(domain)
		if err != nil {
			return nil, fmt.Errorf("resolving %s: %w", domain, err)
		}
		for _, addr := range addrs {
			if net.ParseIP(addr).To4() == nil {
				continue // skip IPv6
			}
			if !seen[addr] {
				seen[addr] = true
				ips = append(ips, addr)
			}
		}
	}
	// Empty allow list is legal (deny everything for the network); only
	// fail when the operator listed domains and none resolved.
	if len(ips) == 0 && len(domains) > 0 {
		return nil, fmt.Errorf("no IPv4 addresses resolved for %v", domains)
	}
	return ips, nil
}

// State file: `<network>: <ip1>,<ip2>,...` one per line.
func readState() map[string][]string {
	out := map[string][]string{}
	data, err := os.ReadFile(boot.EgressStatePath)
	if err != nil {
		return out
	}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		name, ipsStr, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		name = strings.TrimSpace(name)
		var ips []string
		for _, ip := range strings.Split(ipsStr, ",") {
			ip = strings.TrimSpace(ip)
			if ip != "" {
				ips = append(ips, ip)
			}
		}
		out[name] = ips
	}
	return out
}

func writeState(state map[string][]string) error {
	var b strings.Builder
	for name, ips := range state {
		fmt.Fprintf(&b, "%s: %s\n", name, strings.Join(ips, ","))
	}
	return os.WriteFile(boot.EgressStatePath, []byte(b.String()), 0600)
}

// difference returns elements in a that are not in b.
func difference(a, b []string) []string {
	inB := map[string]bool{}
	for _, s := range b {
		inB[s] = true
	}
	var result []string
	for _, s := range a {
		if !inB[s] {
			result = append(result, s)
		}
	}
	return result
}
