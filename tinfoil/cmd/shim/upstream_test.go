package main

import (
	"testing"

	"tinfoil/internal/containernet"
)

func TestResolveUpstreamHostUsesPinnedShimAddress(t *testing.T) {
	if got := resolveUpstreamHost("ignored"); got != containernet.ShimUpstreamIP {
		t.Fatalf("resolveUpstreamHost() = %q, want %q", got, containernet.ShimUpstreamIP)
	}
}
