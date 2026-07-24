package main

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	shimconfig "tinfoil/internal/config"
)

func TestNetworkInterfaceAtPCIFollowsMeasuredDevice(t *testing.T) {
	root := t.TempDir()
	netDir := filepath.Join(root, "0000:00:02.0", "virtio0", "net", "ens2")
	if err := os.MkdirAll(netDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "0000:00:03.0", "virtio1", "net", "ens3"), 0755); err != nil {
		t.Fatal(err)
	}

	got, err := networkInterfaceAtPCI(root, "0000:00:02.0")
	if err != nil {
		t.Fatal(err)
	}
	if got != "ens2" {
		t.Fatalf("networkInterfaceAtPCI() = %q, want ens2", got)
	}
}

func TestNetworkInterfaceAtPCIRejectsAmbiguousTopology(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"ens2", "ens3"} {
		if err := os.MkdirAll(
			filepath.Join(root, "0000:00:02.0", "virtio0", "net", name),
			0755,
		); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := networkInterfaceAtPCI(root, "0000:00:02.0"); err == nil {
		t.Fatal("networkInterfaceAtPCI() accepted ambiguous topology")
	}
}

func TestWaitForNetworkInterfacePollsUntilSysfsAppears(t *testing.T) {
	root := t.TempDir()
	createErr := make(chan error, 1)
	go func() {
		time.Sleep(20 * time.Millisecond)
		createErr <- os.MkdirAll(
			filepath.Join(root, "0000:00:02.0", "virtio0", "net", "ens2"),
			0755,
		)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	got, err := waitForNetworkInterface(ctx, root, "0000:00:02.0", 5*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-createErr; err != nil {
		t.Fatal(err)
	}
	if got != "ens2" {
		t.Fatalf("waitForNetworkInterface() = %q, want ens2", got)
	}
}

func TestApplyStaticNetworkUsesFixedIPv4Contract(t *testing.T) {
	called := false
	configure := func(_ context.Context, iface string, prefix netip.Prefix, gateway netip.Addr) error {
		called = true
		if iface != "ens2" || prefix.String() != "100.64.0.42/20" || gateway.String() != "100.64.0.1" {
			t.Fatalf("configure(%q, %s, %s)", iface, prefix, gateway)
		}
		return nil
	}
	config := shimconfig.ExternalNetworkConfig{
		Address: "100.64.0.42/20",
		Gateway: "100.64.0.1",
	}
	if err := applyStaticNetwork(context.Background(), "ens2", &config, configure); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("network configurer was not called")
	}
}

func TestVerifyFixedResolverAcceptsExactRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resolv.conf")
	if err := os.WriteFile(path, []byte(fixedResolver), 0644); err != nil {
		t.Fatal(err)
	}
	if err := verifyFixedResolver(path); err != nil {
		t.Fatalf("verifyFixedResolver() = %v", err)
	}
}

func TestVerifyFixedResolverFailsClosed(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*testing.T, string)
	}{
		{
			name: "missing",
			setup: func(_ *testing.T, _ string) {
			},
		},
		{
			name: "symlink",
			setup: func(t *testing.T, path string) {
				t.Helper()
				target := filepath.Join(filepath.Dir(path), "target")
				if err := os.WriteFile(target, []byte(fixedResolver), 0644); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "directory",
			setup: func(t *testing.T, path string) {
				t.Helper()
				if err := os.Mkdir(path, 0755); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "mismatch",
			setup: func(t *testing.T, path string) {
				t.Helper()
				contents := "nameserver 1.1.1.1\nnameserver 8.8.8.8\n"
				if err := os.WriteFile(path, []byte(contents), 0644); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "extra bytes",
			setup: func(t *testing.T, path string) {
				t.Helper()
				if err := os.WriteFile(path, []byte(fixedResolver+"search example.com\n"), 0644); err != nil {
					t.Fatal(err)
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "resolv.conf")
			test.setup(t, path)
			if err := verifyFixedResolver(path); err == nil {
				t.Fatal("verifyFixedResolver() accepted invalid resolver")
			}
		})
	}
}

func TestMeasuredResolverAssetMatchesFixedContract(t *testing.T) {
	path := "../../../image/rootfs/etc/resolv.conf"
	if err := verifyFixedResolver(path); err != nil {
		t.Fatalf("measured resolver asset: %v", err)
	}
}

func TestApplyStaticNetworkPropagatesNetlinkFailure(t *testing.T) {
	config := &shimconfig.ExternalNetworkConfig{
		Address: "100.64.0.42/20",
		Gateway: "100.64.0.1",
	}
	configure := func(context.Context, string, netip.Prefix, netip.Addr) error {
		return errors.New("permission denied")
	}
	err := applyStaticNetwork(context.Background(), "ens2", config, configure)
	if err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("netlink failure = %v", err)
	}
}

func TestApplyStaticNetworkRejectsNonIPv4Configuration(t *testing.T) {
	tests := []struct {
		config shimconfig.ExternalNetworkConfig
		want   string
	}{
		{config: shimconfig.ExternalNetworkConfig{Address: "2001:db8::1/64", Gateway: "100.64.0.1"}, want: `configured prefix "2001:db8::1/64" is not IPv4`},
		{config: shimconfig.ExternalNetworkConfig{Address: "100.64.0.42/20", Gateway: "2001:db8::1"}, want: `configured gateway "2001:db8::1" is not IPv4`},
		{config: shimconfig.ExternalNetworkConfig{Address: "invalid", Gateway: "100.64.0.1"}, want: `parse configured IPv4 prefix "invalid"`},
	}
	for _, test := range tests {
		called := false
		err := applyStaticNetwork(context.Background(), "ens2", &test.config,
			func(context.Context, string, netip.Prefix, netip.Addr) error {
				called = true
				return nil
			})
		if err == nil || !strings.Contains(err.Error(), test.want) || strings.Contains(err.Error(), "<nil>") || called {
			t.Fatalf("applyStaticNetwork(%+v) = %v, called=%t", test.config, err, called)
		}
	}
}
