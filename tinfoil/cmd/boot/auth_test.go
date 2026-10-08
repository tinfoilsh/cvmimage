package main

import (
	"testing"

	shimconfig "tinfoil/internal/config"
)

// A secret name cannot carry a hyphen, so a hyphenated registry host is only
// reachable through REGISTRY_<KEY>_HOST. Decoding the key alone must still
// work for the provider registries the controlplane names directly.
func TestRegistryHost(t *testing.T) {
	ext := &shimconfig.ExternalConfig{Secrets: map[string]string{
		"REGISTRY_HARBOR_MY_COMPANY_COM_HOST": "harbor.my-company.com",
		"REGISTRY_QUAY_IO_HOST":               "null",
	}}

	tests := []struct {
		hostPart string
		want     string
	}{
		{"HARBOR_MY_COMPANY_COM", "harbor.my-company.com"},
		{"GHCR_IO", "ghcr.io"},
		{"QUAY_IO", "quay.io"},
	}
	for _, tc := range tests {
		if got := registryHost(ext, tc.hostPart); got != tc.want {
			t.Errorf("registryHost(%q) = %q, want %q", tc.hostPart, got, tc.want)
		}
	}
}
