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

	"gopkg.in/yaml.v3"
)

const refreshInterval = 60 * time.Second

func init() {
	log.SetFlags(0)
}

type egressConfig struct {
	TrustedDomains []string `yaml:"trusted-domains"`
}

func main() {
	if err := run(); err != nil {
		log.Printf("tinfoil-egress: %v", err)
		os.Exit(1)
	}
}

func run() error {
	domains, err := loadDomains()
	if err != nil {
		return err
	}
	if len(domains) == 0 {
		log.Println("no trusted domains configured, exiting")
		return nil
	}

	prev := readState()

	// Initial population must succeed before notifying systemd; tinfoil-boot
	// blocks on `systemctl start` until READY=1 so any failure here surfaces
	// as a boot error.
	next, err := refresh(domains, prev)
	if err != nil {
		return fmt.Errorf("initial population: %w", err)
	}
	prev = next
	notifyReady()
	log.Printf("initial population: %d IP(s) resolved", len(prev))

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
			next, err := refresh(domains, prev)
			if err != nil {
				log.Printf("refresh failed: %v", err)
				continue
			}
			prev = next
		}
	}
}

func loadDomains() ([]string, error) {
	data, err := os.ReadFile(boot.EgressConfigPath)
	if err != nil {
		return nil, fmt.Errorf("reading egress config: %w", err)
	}
	var cfg egressConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing egress config: %w", err)
	}
	return cfg.TrustedDomains, nil
}

func refresh(domains, prev []string) ([]string, error) {
	current, err := resolve(domains)
	if err != nil {
		return nil, err
	}

	// Defensive: ensure the set exists. Normally created by tinfoil-boot.
	exec.Command("nft", "add", "set", "inet", "tinfoil", "container-outgoing-allow",
		"{ type ipv4_addr; }").Run()

	// Flushing and reloading could lead to a race condition where new outgoing
	// connections that should be allowed are not, so instead we calculate the
	// IPs to add and the set of IPs to remove from the set.
	toAdd := difference(current, prev)
	toRemove := difference(prev, current)

	if len(toAdd) == 0 && len(toRemove) == 0 {
		return current, nil
	}

	// Commit add+remove in one transaction so the set never appears with only
	// one half of the delta applied.
	var script strings.Builder
	if len(toAdd) > 0 {
		fmt.Fprintf(&script, "add element inet tinfoil container-outgoing-allow { %s }\n",
			strings.Join(toAdd, ", "))
	}
	if len(toRemove) > 0 {
		fmt.Fprintf(&script, "delete element inet tinfoil container-outgoing-allow { %s }\n",
			strings.Join(toRemove, ", "))
	}

	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script.String())
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("updating container-outgoing-allow set: %w (%s)", err, out)
	}

	if err := writeState(current); err != nil {
		return nil, fmt.Errorf("persisting state: %w", err)
	}
	return current, nil
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

// notifyReady sends READY=1 over the systemd NOTIFY_SOCKET so the unit
// transitions to active only after the first successful resolution. No-op
// when not running under systemd Type=notify (NOTIFY_SOCKET unset).
func notifyReady() {
	addr := os.Getenv("NOTIFY_SOCKET")
	if addr == "" {
		return
	}
	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: addr, Net: "unixgram"})
	if err != nil {
		log.Printf("sd_notify dial: %v", err)
		return
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("READY=1")); err != nil {
		log.Printf("sd_notify write: %v", err)
	}
}
