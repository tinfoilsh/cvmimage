package main

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"tinfoil/internal/boot"
	shimconfig "tinfoil/internal/config"
)

const (
	networkReadyTimeout = 90 * time.Second
	ipBinary            = "/usr/sbin/ip"
)

var sysBusPCIDevices = "/sys/bus/pci/devices"

type commandRunner func(context.Context, string, ...string) ([]byte, error)

func runCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

func configureGuestNetwork(ctx context.Context, config *shimconfig.ExternalNetworkConfig) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, networkReadyTimeout)
	defer cancel()

	iface, err := networkInterfaceAtPCI(sysBusPCIDevices, boot.ExternalNICPCIAddress)
	if err != nil {
		return "", err
	}
	if err := applyStaticNetwork(ctx, iface, config, runCommand); err != nil {
		return "", err
	}
	return fmt.Sprintf(
		"static network configured; interface=%s address=%s gateway=%s",
		iface, config.Address, config.Gateway,
	), nil
}

func networkInterfaceAtPCI(sysBusPCI, pciAddress string) (string, error) {
	var matches []string
	for _, pattern := range []string{
		filepath.Join(sysBusPCI, pciAddress, "net", "*"),
		filepath.Join(sysBusPCI, pciAddress, "virtio*", "net", "*"),
	} {
		found, err := filepath.Glob(pattern)
		if err != nil {
			return "", err
		}
		matches = append(matches, found...)
	}
	sort.Strings(matches)
	matches = compactStrings(matches)
	if len(matches) != 1 {
		return "", fmt.Errorf(
			"expected one network interface at PCI device %s, found %d",
			pciAddress, len(matches),
		)
	}
	return filepath.Base(matches[0]), nil
}

func compactStrings(values []string) []string {
	if len(values) < 2 {
		return values
	}
	out := values[:1]
	for _, value := range values[1:] {
		if value != out[len(out)-1] {
			out = append(out, value)
		}
	}
	return out
}

func applyStaticNetwork(
	ctx context.Context,
	iface string,
	config *shimconfig.ExternalNetworkConfig,
	run commandRunner,
) error {
	commands := [][]string{
		{"link", "set", "dev", iface, "up"},
		{"addr", "replace", config.Address, "dev", iface},
		{"route", "replace", "default", "via", config.Gateway, "dev", iface},
	}
	for _, args := range commands {
		output, err := run(ctx, ipBinary, args...)
		if err == nil {
			continue
		}
		detail := strings.TrimSpace(string(output))
		if detail != "" {
			return fmt.Errorf("ip %s: %w: %s", strings.Join(args, " "), err, detail)
		}
		return fmt.Errorf("ip %s: %w", strings.Join(args, " "), err)
	}
	return nil
}
