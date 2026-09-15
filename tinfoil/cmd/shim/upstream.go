package main

import "tinfoil/internal/containernet"

// resolveUpstreamHost returns the fixed shim-net address assigned to the
// upstream container by tinfoil-boot.
func resolveUpstreamHost(_ string) string {
	return containernet.ShimUpstreamIP
}
