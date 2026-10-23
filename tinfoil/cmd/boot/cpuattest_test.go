package main

import (
	"os"
	"testing"

	"tinfoil/internal/attestationmaterial"
	"tinfoil/internal/config"
)

func TestDummyAttestationSkipsCollateralRequest(t *testing.T) {
	path := t.TempDir() + "/collateral-request.json"
	request, err := writeCollateralRequest(path, nil, config.Metadata{})
	if err != nil {
		t.Fatal(err)
	}
	if request.Version == attestationmaterial.RequestVersionDocument {
		t.Fatal("dummy attestation produced a document request")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("dummy collateral request was written: %v", err)
	}
}
