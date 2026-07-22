package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
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

func TestApplyStaticNetworkUsesFixedIPCommands(t *testing.T) {
	var calls []string
	run := func(_ context.Context, name string, args ...string) ([]byte, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		return nil, nil
	}
	config := shimconfig.ExternalNetworkConfig{
		Address: "100.64.0.42/20",
		Gateway: "100.64.0.1",
	}
	if err := applyStaticNetwork(context.Background(), "ens2", &config, run); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"/usr/sbin/ip link set dev ens2 up",
		"/usr/sbin/ip addr flush dev ens2",
		"/usr/sbin/ip route flush dev ens2",
		"/usr/sbin/ip addr replace 100.64.0.42/20 dev ens2",
		"/usr/sbin/ip route replace default via 100.64.0.1 dev ens2",
	}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("calls = %v, want %v", calls, want)
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

func TestApplyStaticNetworkPropagatesCommandFailure(t *testing.T) {
	config := &shimconfig.ExternalNetworkConfig{
		Address: "100.64.0.42/20",
		Gateway: "100.64.0.1",
	}
	run := func(_ context.Context, _ string, _ ...string) ([]byte, error) {
		return []byte("permission denied"), errors.New("exit status 2")
	}
	err := applyStaticNetwork(context.Background(), "ens2", config, run)
	if err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("command failure = %v", err)
	}
}
