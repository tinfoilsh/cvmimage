package main

import (
	"os"
	"path/filepath"
	"testing"

	"tinfoil/inference/internal/containernet"
)

func TestResolveUpstreamHostUsesPinnedShimAddress(t *testing.T) {
	if got := shimSpec().UpstreamHost; got != containernet.ShimUpstreamIP {
		t.Fatalf("UpstreamHost() = %q, want %q", got, containernet.ShimUpstreamIP)
	}
}

func writeRuntimeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "runtime-config.yml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestPublishedPorts(t *testing.T) {
	targets, err := publishedPorts(writeRuntimeConfig(t, "containers:\n  - name: sandbox\n    ports: ['2300:25565', '2301:8080']\n  - name: quiet\n"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(targets) != 2 || !targets["2300"] || !targets["2301"] {
		t.Fatalf("targets = %v", targets)
	}
	if _, err := publishedPorts(writeRuntimeConfig(t, "containers:\n  - name: sandbox\n    ports: ['25565']\n")); err == nil {
		t.Fatal("expected an error for a port without a mapping")
	}
}
