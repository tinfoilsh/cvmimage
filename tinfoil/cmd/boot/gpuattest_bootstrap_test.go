package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	shimconfig "tinfoil/internal/config"
	"tinfoil/internal/nvidia"
)

func TestGPUAttestationBootstrapFailsClosedInRealAndDummyModes(t *testing.T) {
	for _, dummy := range []bool{false, true} {
		t.Run(map[bool]string{false: "real", true: "dummy"}[dummy], func(t *testing.T) {
			directory := t.TempDir()
			path := filepath.Join(directory, "status")
			config := &Config{GPUs: 8, ShimCfg: &shimconfig.Config{DummyAttestation: dummy}}

			if err := nvidia.WriteBootstrapStatus(path, nvidia.ReadyBootstrapStatus(8)); err != nil {
				t.Fatal(err)
			}
			if err := validateGPUAttestationBootstrap(path, config); err != nil {
				t.Fatalf("matching ready status failed: %v", err)
			}

			invalid := []struct {
				name  string
				setup func() string
			}{
				{name: "missing", setup: func() string { return filepath.Join(directory, "missing") }},
				{name: "malformed", setup: func() string {
					candidate := filepath.Join(directory, "malformed")
					if err := os.WriteFile(candidate, []byte("tinfoil-nvidia-bootstrap-v1:ready:08\n"), 0600); err != nil {
						t.Fatal(err)
					}
					return candidate
				}},
				{name: "oversized", setup: func() string {
					candidate := filepath.Join(directory, "oversized")
					if err := os.WriteFile(candidate, []byte(strings.Repeat("x", 41)), 0600); err != nil {
						t.Fatal(err)
					}
					return candidate
				}},
				{name: "symlink", setup: func() string {
					candidate := filepath.Join(directory, "symlink")
					if err := os.Symlink(path, candidate); err != nil {
						t.Fatal(err)
					}
					return candidate
				}},
				{name: "failed", setup: func() string {
					candidate := filepath.Join(directory, "failed")
					if err := nvidia.WriteBootstrapStatus(candidate, nvidia.FailedBootstrapStatus()); err != nil {
						t.Fatal(err)
					}
					return candidate
				}},
				{name: "count-mismatch", setup: func() string {
					candidate := filepath.Join(directory, "mismatch")
					if err := nvidia.WriteBootstrapStatus(candidate, nvidia.ReadyBootstrapStatus(1)); err != nil {
						t.Fatal(err)
					}
					return candidate
				}},
				{name: "no-gpu-mismatch", setup: func() string {
					candidate := filepath.Join(directory, "no-gpu")
					if err := nvidia.WriteBootstrapStatus(candidate, nvidia.NoGPUBootstrapStatus()); err != nil {
						t.Fatal(err)
					}
					return candidate
				}},
			}
			for _, test := range invalid {
				t.Run(test.name, func(t *testing.T) {
					if err := validateGPUAttestationBootstrap(test.setup(), config); err == nil {
						t.Fatal("invalid bootstrap status passed GPU attestation")
					}
				})
			}
		})
	}
}

func TestGPUAttestationBootstrapRequiresExplicitNoGPUStatus(t *testing.T) {
	path := filepath.Join(t.TempDir(), "status")
	config := &Config{GPUs: 0, ShimCfg: &shimconfig.Config{DummyAttestation: true}}
	if err := nvidia.WriteBootstrapStatus(path, nvidia.NoGPUBootstrapStatus()); err != nil {
		t.Fatal(err)
	}
	if err := validateGPUAttestationBootstrap(path, config); err != nil {
		t.Fatalf("explicit no-GPU status failed: %v", err)
	}
	if err := nvidia.WriteBootstrapStatus(path, nvidia.ReadyBootstrapStatus(1)); err != nil {
		t.Fatal(err)
	}
	if err := validateGPUAttestationBootstrap(path, config); err == nil {
		t.Fatal("ready status passed gpus=0 config")
	}
}
