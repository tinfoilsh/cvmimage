package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"time"

	"golang.org/x/sys/unix"
	"tinfoil/internal/boot"
	shimconfig "tinfoil/internal/config"
	"tinfoil/internal/rtnetlink"
)

const (
	networkReadyTimeout = 90 * time.Second
	networkPollInterval = 100 * time.Millisecond
	resolverPath        = "/etc/resolv.conf"
	primaryNameserver   = "1.1.1.1"
	secondaryNameserver = "1.0.0.1"
	fixedResolver       = "nameserver 1.1.1.1\nnameserver 1.0.0.1\n"
)

var sysBusPCIDevices = "/sys/bus/pci/devices"
var errNetworkInterfaceNotFound = errors.New("network interface not found")

type networkConfigurer func(context.Context, string, netip.Prefix, netip.Addr) error

func configureGuestNetwork(ctx context.Context, config *shimconfig.ExternalNetworkConfig) (string, error) {
	if err := verifyFixedResolver(resolverPath); err != nil {
		return "", err
	}
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
	if err := applyStaticNetwork(ctx, iface, config, rtnetlink.ConfigureIPv4); err != nil {
		return "", err
	}
	return fmt.Sprintf(
		"static network configured; interface=%s address=%s gateway=%s dns=%s",
		iface, config.Address, config.Gateway, primaryNameserver+","+secondaryNameserver,
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

func verifyFixedResolver(path string) error {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return fmt.Errorf("open fixed resolver %s: %w", path, err)
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("stat fixed resolver %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("fixed resolver %s is not a regular file", path)
	}
	contents, err := io.ReadAll(file)
	if err != nil {
		return fmt.Errorf("read fixed resolver %s: %w", path, err)
	}
	if !bytes.Equal(contents, []byte(fixedResolver)) {
		return fmt.Errorf("fixed resolver %s does not match measured contents", path)
	}
	return nil
}

func applyStaticNetwork(
	ctx context.Context,
	iface string,
	config *shimconfig.ExternalNetworkConfig,
	configure networkConfigurer,
) error {
	prefix, err := netip.ParsePrefix(config.Address)
	if err != nil || !prefix.Addr().Is4() {
		return fmt.Errorf("parse configured IPv4 prefix %q: %w", config.Address, err)
	}
	gateway, err := netip.ParseAddr(config.Gateway)
	if err != nil || !gateway.Is4() {
		return fmt.Errorf("parse configured IPv4 gateway %q: %w", config.Gateway, err)
	}
	return configure(ctx, iface, prefix, gateway)
}
