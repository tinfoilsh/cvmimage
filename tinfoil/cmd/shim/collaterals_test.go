package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	wire "github.com/tinfoilsh/tinfoil-go/collaterals"
	"github.com/tinfoilsh/tinfoil-go/verify/document/collateral"

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
	source, err := newCollateralSource(wire.Request{Repo: "repo", Platform: attestation.PlatformDummy}, &config.Config{}, "")
	if err != nil {
		t.Fatal(err)
	}
	if source != nil {
		t.Fatal("dummy collateral source was created")
	}
}

func TestLocalCollateralIncludesExactConfig(t *testing.T) {
	request := wire.Request{Profile: wire.FormatV3, Platform: attestation.PlatformTDX, QuoteBase64: "cXVvdGU=",
		Runtime: "0.15.1-rc.1@sha256:" + strings.Repeat("a", 64)}
	platform := collateral.Entry{ID: collateral.PlatformID, Role: collateral.RoleReferenceValues,
		Format: collateral.SigstorePlatformV1Format, Data: []byte(`{"sigstore_bundle":{}}`)}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var got wire.Request
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil || got != request {
			t.Errorf("ATC request = %#v, error = %v", got, err)
		}
		_ = json.NewEncoder(w).Encode(wire.Response{Format: wire.FormatV3, ExpiresAt: time.Now().Add(time.Hour),
			Collateral: []collateral.Entry{platform}})
	}))
	defer server.Close()
	path := filepath.Join(t.TempDir(), "config.yaml")
	data := []byte("# Preserve exact bytes.\r\ncvm-version: " + request.Runtime + "\r\n")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	source, err := newCollateralSource(request, &config.Config{ATC: server.URL}, path)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		response, err := source.Current(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if response.Format != wire.FormatV3 || len(response.Collateral) != 2 || !reflect.DeepEqual(response.Collateral[0], platform) {
			t.Fatalf("unexpected collateral response: %#v", response)
		}
		entry := response.Collateral[1]
		if entry.ID != collateral.ConfigID || entry.Role != collateral.RoleReferenceValues || entry.Format != collateral.ConfigV1Format {
			t.Fatalf("unexpected config collateral: %#v", entry)
		}
		var decoded struct {
			Config []byte `json:"config_base64"`
		}
		if err := json.Unmarshal(entry.Data, &decoded); err != nil || !bytes.Equal(decoded.Config, data) {
			t.Fatalf("config = %q, error = %v", decoded.Config, err)
		}
		entry.Data[0] = 'x'
	}
}

func TestLoadConfigCollateralRequest(t *testing.T) {
	want := wire.Request{Profile: wire.FormatV3, Platform: attestation.PlatformTDX, QuoteBase64: "cXVvdGU=",
		Repo: "org/project", Tag: "v1", Digest: strings.Repeat("a", 64)}
	got, err := loadCollateralRequest(writeCollateralRequestArtifact(t, want))
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("request = %#v, error = %v", got, err)
	}
	want.Repo, want.Tag, want.Digest = "", "", ""
	want.Runtime = "0.15.1-rc.1@sha256:" + strings.Repeat("a", 64)
	got, err = loadCollateralRequest(writeCollateralRequestArtifact(t, want))
	if err != nil || got != want {
		t.Fatalf("local request = %#v, error = %v", got, err)
	}
	want.Repo = "org/project"
	if _, err := loadCollateralRequest(writeCollateralRequestArtifact(t, want)); err == nil {
		t.Fatal("mixed registry and local collateral request accepted")
	}

}

func TestLoadCollateralRequestRejectsIncompleteArtifact(t *testing.T) {
	digest := strings.Repeat("a", 64)
	for name, request := range map[string]wire.Request{
		"empty":            {},
		"missing quote":    {Repo: "repo", Platform: attestation.PlatformTDX},
		"missing repo":     {Platform: attestation.PlatformTDX, QuoteBase64: "cXVvdGU="},
		"missing revision": {Profile: wire.FormatV3, Repo: "org/project", Digest: digest, Platform: attestation.PlatformTDX, QuoteBase64: "cXVvdGU="},
		"missing digest":   {Profile: wire.FormatV3, Repo: "org/project", Tag: "v1", Platform: attestation.PlatformTDX, QuoteBase64: "cXVvdGU="},
		"missing project":  {Profile: wire.FormatV3, Tag: "v1", Digest: digest, Platform: attestation.PlatformTDX, QuoteBase64: "cXVvdGU="},
		"missing profile":  {Repo: "org/project", Tag: "v1", Digest: digest, Platform: attestation.PlatformTDX, QuoteBase64: "cXVvdGU="},
		"unknown profile":  {Profile: "unknown", Repo: "org/project", Tag: "v1", Digest: digest, Platform: attestation.PlatformTDX, QuoteBase64: "cXVvdGU="},
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
