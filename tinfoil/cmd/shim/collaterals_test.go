package main

import (
	"encoding/json"
	"os"
	"testing"

	wire "github.com/tinfoilsh/tinfoil-go/verifier/collaterals"

	"tinfoil/internal/attestation"
	"tinfoil/internal/config"
)

func TestLoadCollateralRequest(t *testing.T) {
	want := wire.Request{
		Repo:        "tinfoilsh/workload",
		Tag:         "v1",
		Platform:    "tdx",
		QuoteBase64: "cXVvdGU=",
	}
	got, err := loadCollateralRequest(writeCollateralRequestArtifact(t, want))
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("request = %#v, want %#v", got, want)
	}
}

func TestNewCollateralSourceSkipsDummy(t *testing.T) {
	source, err := newCollateralSource(wire.Request{Repo: "repo", Platform: attestation.PlatformDummy}, &config.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if source != nil {
		t.Fatal("dummy collateral source was created")
	}
}

func TestLoadCollateralRequestRejectsIncompleteArtifact(t *testing.T) {
	for name, request := range map[string]wire.Request{
		"empty":         {},
		"missing quote": {Repo: "repo", Platform: attestation.PlatformTDX},
		"missing repo":  {Platform: attestation.PlatformTDX, QuoteBase64: "cXVvdGU="},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := loadCollateralRequest(writeCollateralRequestArtifact(t, request)); err == nil {
				t.Fatal("incomplete collateral request accepted")
			}
		})
	}
}

func writeCollateralRequestArtifact(t *testing.T, request wire.Request) string {
	t.Helper()
	data, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	path := t.TempDir() + "/collateral-request.json"
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
