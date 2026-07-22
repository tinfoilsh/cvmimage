package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

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

func TestApplyStaticNetworkUsesFixedIPCommands(t *testing.T) {
	var calls []string
	run := func(_ context.Context, name string, args ...string) ([]byte, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		return nil, nil
	}
	config := shimconfig.ExternalNetworkConfig{
		Version: 1,
		Address: "100.64.0.42/20",
		Gateway: "100.64.0.1",
	}
	if err := applyStaticNetwork(context.Background(), "ens2", &config, run); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"/usr/sbin/ip link set dev ens2 up",
		"/usr/sbin/ip addr replace 100.64.0.42/20 dev ens2",
		"/usr/sbin/ip route replace default via 100.64.0.1 dev ens2",
	}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("calls = %v, want %v", calls, want)
	}
}

func TestApplyStaticNetworkPropagatesCommandFailure(t *testing.T) {
	config := &shimconfig.ExternalNetworkConfig{
		Version: 1,
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
