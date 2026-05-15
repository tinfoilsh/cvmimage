package main

import (
	"strings"
	"testing"

	shimconfig "tinfoil/internal/config"
)

func TestValidateNetwork(t *testing.T) {
	tests := []struct {
		name       string
		cfg        Config
		wantErr    bool
		wantErrSub string
	}{
		{
			name: "empty network → deny posture is legal",
			cfg:  Config{},
		},
		{
			name: "trusted-domains only",
			cfg: Config{Network: NetworkConfig{
				TrustedDomains: []string{"api.exa.ai", "api.tinfoil.sh"},
			}},
		},
		{
			name: "trust-all-domains only",
			cfg: Config{Network: NetworkConfig{
				TrustAllDomains: true,
			}},
		},
		{
			name: "trust-all-domains: false treated as absent",
			cfg: Config{Network: NetworkConfig{
				TrustedDomains:  []string{"api.exa.ai"},
				TrustAllDomains: false,
			}},
		},
		{
			name: "trust-all-domains: true plus a non-empty allowlist → reject",
			cfg: Config{Network: NetworkConfig{
				TrustedDomains:  []string{"api.exa.ai"},
				TrustAllDomains: true,
			}},
			wantErr:    true,
			wantErrSub: "mutually exclusive",
		},
		{
			name: `trusted-domains: ["*"] → reject with pointer to the boolean`,
			cfg: Config{Network: NetworkConfig{
				TrustedDomains: []string{"*"},
			}},
			wantErr:    true,
			wantErrSub: "trust-all-domains: true",
		},
		{
			name: `wildcard subdomain → reject as not yet supported`,
			cfg: Config{Network: NetworkConfig{
				TrustedDomains: []string{"*.model.tinfoil.sh"},
			}},
			wantErr:    true,
			wantErrSub: "not yet supported",
		},
		{
			name: "IP literal → reject",
			cfg: Config{Network: NetworkConfig{
				TrustedDomains: []string{"1.2.3.4"},
			}},
			wantErr:    true,
			wantErrSub: "IP literals",
		},
		{
			name: "overlong hostname (>253 bytes) → reject",
			cfg: Config{Network: NetworkConfig{
				// 5 × 63-char labels joined by dots is 319 chars, comfortably
				// over the 253-byte DNS cap while keeping each label legal.
				TrustedDomains: []string{
					strings.Repeat("a", 63) + "." +
						strings.Repeat("b", 63) + "." +
						strings.Repeat("c", 63) + "." +
						strings.Repeat("d", 63) + "." +
						strings.Repeat("e", 63),
				},
			}},
			wantErr:    true,
			wantErrSub: "253-byte DNS limit",
		},
		{
			name: "container.network_mode → reject with migration pointer",
			cfg: Config{Containers: []Container{
				{Name: "doc-upload", NetworkMode: "host"},
			}},
			wantErr:    true,
			wantErrSub: "network_mode is removed",
		},
		{
			name: "shim.upstream-container matches a container → accept",
			cfg: Config{
				ShimCfg:    &shimconfig.Config{UpstreamContainer: "router"},
				Containers: []Container{{Name: "router"}, {Name: "worker"}},
			},
		},
		{
			name: "shim.upstream-container with no matching container → reject",
			cfg: Config{
				ShimCfg:    &shimconfig.Config{UpstreamContainer: "ghost"},
				Containers: []Container{{Name: "router"}},
			},
			wantErr:    true,
			wantErrSub: "does not match any containers",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateNetwork(&tt.cfg)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErrSub)
				}
				if !strings.Contains(err.Error(), tt.wantErrSub) {
					t.Fatalf("error mismatch: got %q, want substring %q", err, tt.wantErrSub)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
