package main

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	wire "github.com/tinfoilsh/tinfoil-go/verifier/collaterals"
	"github.com/tinfoilsh/tinfoil-go/verifier/document"

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

func TestLoadConfigCollateralRequest(t *testing.T) {
	want := wire.Request{Profile: wire.ProfileIGVMV1, Platform: attestation.PlatformTDX, QuoteBase64: "cXVvdGU=",
		Runtime: &document.RuntimeReference{Repo: "tinfoilsh/cvmimage", Tag: "v0.15.0", Digest: strings.Repeat("b", 64)},
		Config:  &document.ConfigReference{Name: "/org/project/v1", Digest: strings.Repeat("a", 64)}}
	got, err := loadCollateralRequest(writeCollateralRequestArtifact(t, want))
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("request = %#v, error = %v", got, err)
	}
}

func TestLoadCollateralRequestRejectsIncompleteArtifact(t *testing.T) {
	config := &document.ConfigReference{Name: "/org/project/v1", Digest: strings.Repeat("a", 64)}
	runtime := &document.RuntimeReference{Repo: "tinfoilsh/cvmimage", Tag: "v0.15.0", Digest: strings.Repeat("b", 64)}
	for name, request := range map[string]wire.Request{
		"empty":           {},
		"missing quote":   {Repo: "repo", Platform: attestation.PlatformTDX},
		"missing repo":    {Platform: attestation.PlatformTDX, QuoteBase64: "cXVvdGU="},
		"missing runtime": {Profile: wire.ProfileIGVMV1, Config: config, Platform: attestation.PlatformTDX, QuoteBase64: "cXVvdGU="},
		"missing config":  {Profile: wire.ProfileIGVMV1, Runtime: runtime, Platform: attestation.PlatformTDX, QuoteBase64: "cXVvdGU="},
		"mixed sources":   {Profile: wire.ProfileIGVMV1, Runtime: runtime, Config: config, Repo: "org/repo", Platform: attestation.PlatformTDX, QuoteBase64: "cXVvdGU="},
		"missing profile": {Runtime: runtime, Config: config, Platform: attestation.PlatformTDX, QuoteBase64: "cXVvdGU="},
		"unknown profile": {Profile: "unknown", Runtime: runtime, Config: config, Platform: attestation.PlatformTDX, QuoteBase64: "cXVvdGU="},
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
