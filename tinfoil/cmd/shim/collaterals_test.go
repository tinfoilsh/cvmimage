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
	data, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	path := t.TempDir() + "/collateral-request.json"
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	got, err := loadCollateralRequest(path)
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
			data, err := json.Marshal(request)
			if err != nil {
				t.Fatal(err)
			}
			path := t.TempDir() + "/collateral-request.json"
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := loadCollateralRequest(path); err == nil {
				t.Fatal("incomplete collateral request accepted")
			}
		})
	}
}
