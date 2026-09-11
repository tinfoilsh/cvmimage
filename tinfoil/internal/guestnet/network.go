package guestnet

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"tinfoil/internal/bootstate"
)

const (
	networkReadyTimeout = 90 * time.Second
	networkPollInterval = 100 * time.Millisecond
	ipBinary            = "/usr/sbin/ip"
	resolverPath        = "/etc/resolv.conf"
	primaryNameserver   = "1.1.1.1"
	secondaryNameserver = "1.0.0.1"
	fixedResolver       = "nameserver 1.1.1.1\nnameserver 1.0.0.1\n"
)

var sysBusPCIDevices = "/sys/bus/pci/devices"
var errNetworkInterfaceNotFound = errors.New("network interface not found")

type Config struct {
	Address string `yaml:"address"`
	Gateway string `yaml:"gateway"`
}

type commandRunner func(context.Context, string, ...string) ([]byte, error)

func runCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

func Configure(ctx context.Context, config *Config) (string, error) {
	if err := verifyFixedResolver(resolverPath); err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, networkReadyTimeout)
	defer cancel()

	iface, err := waitForNetworkInterface(
		ctx,
		sysBusPCIDevices,
		bootstate.ExternalNICPCIAddress,
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
	config *Config,
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

func Validate(config *Config) error {
	if config == nil {
		return fmt.Errorf("network section is required")
	}
	prefix, err := netip.ParsePrefix(config.Address)
	if err != nil || !prefix.Addr().Is4() {
		return fmt.Errorf("invalid IPv4 address %q", config.Address)
	}
	if prefix.Bits() > 30 {
		return fmt.Errorf("IPv4 prefix /%d has no distinct guest and gateway addresses", prefix.Bits())
	}
	gateway, err := netip.ParseAddr(config.Gateway)
	if err != nil || !gateway.Is4() {
		return fmt.Errorf("invalid IPv4 gateway %q", config.Gateway)
	}
	if !prefix.Contains(gateway) {
		return fmt.Errorf("gateway %s is outside address subnet %s", config.Gateway, config.Address)
	}

	address := prefix.Addr()
	network := prefix.Masked().Addr()
	broadcast := ipv4Broadcast(prefix)
	if gateway == network || gateway == broadcast {
		return fmt.Errorf("gateway %s is reserved in subnet %s", gateway, prefix)
	}
	if address == network ||
		address == broadcast ||
		address == gateway {
		return fmt.Errorf("address %s is reserved in subnet %s", address, prefix)
	}
	return nil
}

func ipv4Broadcast(prefix netip.Prefix) netip.Addr {
	broadcast := prefix.Masked().Addr().As4()
	for bit := prefix.Bits(); bit < 32; bit++ {
		broadcast[bit/8] |= 1 << (7 - bit%8)
	}
	return netip.AddrFrom4(broadcast)
}
