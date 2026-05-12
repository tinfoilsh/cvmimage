package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"

	"tinfoil/internal/boot"

	"gopkg.in/yaml.v3"
)

func init() {
	log.SetFlags(0)
}

type networkConfig struct {
	TrustedDomains []string `yaml:"trusted-domains"`
}

type config struct {
	Network networkConfig `yaml:"network"`
}

func main() {
	if err := run(); err != nil {
		log.Printf("tinfoil-egress refresh failed: %v", err)
		os.Exit(1)
	}
}

func run() error {
	data, err := os.ReadFile(boot.ConfigPath)
	if err != nil {
		return fmt.Errorf("config not found: %v", err)
	}

	var cfg config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("parsing config: %w", err)
	}

	if len(cfg.Network.TrustedDomains) == 0 {
		return nil
	}

	return refresh(cfg.Network.TrustedDomains)
}

func refresh(domains []string) error {
	current, err := resolve(domains)
	if err != nil {
		return err
	}

	prev := readState()

	// Create the set if it doesn't exist yet
	exec.Command("nft", "add", "set", "inet", "tinfoil", "container-outgoing-allow",
		"{ type ipv4_addr; }").Run()

	// Flushing and reloading could lead to a race condition where new outgoing
	// connections that should be allowed are not, so instead we calculate the
	// IPs to add and the set of IPs to remove from the set
	toAdd := difference(current, prev)
	toRemove := difference(prev, current)

	if len(toAdd) > 0 {
		if out, err := exec.Command("nft", "add", "element", "inet", "tinfoil",
			"container-outgoing-allow",
			"{ "+strings.Join(toAdd, ", ")+" }").CombinedOutput(); err != nil {
			return fmt.Errorf("nft add element: %w (%s)", err, out)
		}
	}

	if len(toRemove) > 0 {
		if out, err := exec.Command("nft", "delete", "element", "inet", "tinfoil",
			"container-outgoing-allow",
			"{ "+strings.Join(toRemove, ", ")+" }").CombinedOutput(); err != nil {
			return fmt.Errorf("nft delete element: %w (%s)", err, out)
		}
	}

	return writeState(current)
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
	if len(ips) == 0 {
		return nil, fmt.Errorf("no IPv4 addresses resolved for %v", domains)
	}
	return ips, nil
}

func readState() []string {
	data, err := os.ReadFile(boot.EgressStatePath)
	if err != nil {
		return nil
	}
	var ips []string
	for line := range strings.SplitSeq(strings.TrimSpace(string(data)), "\n") {
		if line != "" {
			ips = append(ips, line)
		}
	}
	return ips
}

func writeState(ips []string) error {
	return os.WriteFile(boot.EgressStatePath,
		[]byte(strings.Join(ips, "\n")+"\n"), 0600)
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
