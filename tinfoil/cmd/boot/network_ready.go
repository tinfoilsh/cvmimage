package main

import (
	"context"
	"errors"
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
	networkPollInterval = 100 * time.Millisecond
	ipBinary            = "/usr/sbin/ip"
	resolvectlBinary    = "/usr/bin/resolvectl"
)

var sysBusPCIDevices = "/sys/bus/pci/devices"
var errNetworkInterfaceNotFound = errors.New("network interface not found")

type commandRunner func(context.Context, string, ...string) ([]byte, error)

func runCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

func configureGuestNetwork(ctx context.Context, config *shimconfig.ExternalNetworkConfig) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, networkReadyTimeout)
	defer cancel()

	iface, err := waitForNetworkInterface(
		ctx,
		sysBusPCIDevices,
		boot.ExternalNICPCIAddress,
		networkPollInterval,
	)
	if err != nil {
		return "", err
	}
	if err := applyStaticNetwork(ctx, iface, config, runCommand); err != nil {
		return "", err
	}
	return fmt.Sprintf(
		"static network configured; interface=%s address=%s gateway=%s dns=%s",
		iface, config.Address, config.Gateway, config.DNS,
	), nil
}

func waitForNetworkInterface(
	ctx context.Context,
	sysBusPCI string,
	pciAddress string,
	pollInterval time.Duration,
) (string, error) {
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	for {
		iface, err := networkInterfaceAtPCI(sysBusPCI, pciAddress)
		if err == nil {
			return iface, nil
		}
		if !errors.Is(err, errNetworkInterfaceNotFound) {
			return "", err
		}
		select {
		case <-ctx.Done():
			return "", fmt.Errorf("waiting for network interface at PCI device %s: %w", pciAddress, ctx.Err())
		case <-ticker.C:
		}
	}
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
	switch len(matches) {
	case 0:
		return "", fmt.Errorf("%w at PCI device %s", errNetworkInterfaceNotFound, pciAddress)
	case 1:
		return filepath.Base(matches[0]), nil
	default:
		return "", fmt.Errorf(
			"expected one network interface at PCI device %s, found %d",
			pciAddress, len(matches),
		)
	}
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
	commands := []struct {
		name string
		args []string
	}{
		{ipBinary, []string{"link", "set", "dev", iface, "up"}},
		{ipBinary, []string{"addr", "flush", "dev", iface}},
		{ipBinary, []string{"route", "flush", "dev", iface}},
		{ipBinary, []string{"addr", "replace", config.Address, "dev", iface}},
		{ipBinary, []string{"route", "replace", "default", "via", config.Gateway, "dev", iface}},
		{resolvectlBinary, []string{"dns", iface, config.DNS}},
		{resolvectlBinary, []string{"domain", iface, "~."}},
		{resolvectlBinary, []string{"default-route", iface, "yes"}},
	}
	for _, command := range commands {
		output, err := run(ctx, command.name, command.args...)
		if err == nil {
			continue
		}
		detail := strings.TrimSpace(string(output))
		if detail != "" {
			return fmt.Errorf("%s %s: %w: %s", command.name, strings.Join(command.args, " "), err, detail)
		}
		return fmt.Errorf("%s %s: %w", command.name, strings.Join(command.args, " "), err)
	}
	return nil
}
