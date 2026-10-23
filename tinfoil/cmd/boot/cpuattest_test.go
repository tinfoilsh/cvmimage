package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"os"
	"testing"

	"tinfoil/internal/config"
	"tinfoil/internal/legacy"
)

func TestDummyAttestationSkipsHardwareAndCollateral(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		domain string
		config config.Config
	}{
		{domain: "localhost"}, {domain: "enclave.example", config: config.Config{DummyAttestation: true}},
	} {
		cpu, err := fetchCPUAttestation(&NodeIdentity{Domain: tc.domain, TLSKey: key}, &tc.config)
		if err != nil {
			t.Fatal(err)
		}
		if len(cpu.Document) != 0 || cpu.V2Doc == nil || cpu.V2Doc.Format != legacy.DummyV2 {
			t.Fatalf("unexpected dummy attestation: %#v", cpu)
		}
		path := t.TempDir() + "/collateral-request.json"
		request, err := writeCollateralRequest(path, cpu.Document, config.Metadata{})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("dummy collateral request was written: %v", err)
		}
		if _, err := prefetchKeyserverCollateral(context.Background(), &Config{ShimCfg: &tc.config}, request); err == nil {
			t.Fatal("dummy attestation was accepted for keyserver secrets")
		}
	}
}
