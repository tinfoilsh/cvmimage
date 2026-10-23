package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	wire "github.com/tinfoilsh/tinfoil-go/collaterals"
	"github.com/tinfoilsh/tinfoil-go/verify/document"
	"github.com/tinfoilsh/tinfoil-go/verify/document/collateral"

	"tinfoil/internal/attestationmaterial"
	shimconfig "tinfoil/internal/config"
)

func TestConfigCollateralRequestPersistsAndReachesATC(t *testing.T) {
	digest := strings.Repeat("a", 64)
	external, err := decodeExternalConfig([]byte(fmt.Sprintf(`
metadata:
  profile: %s
  repo: org/project
  tag: v1
  digest: %s
network:
  address: 100.64.0.42/20
  gateway: 100.64.0.1
`, wire.FormatV3, digest)))
	if err != nil {
		t.Fatal(err)
	}
	empty, err := document.Build(document.BuildInput{Nonce: make([]byte, document.NonceSize), CollateralFormat: wire.FormatV3}, func([64]byte) (string, []byte, error) {
		return document.SEVSNPReportV1Format, []byte("quote"), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	expected := attestationmaterial.Request{Version: attestationmaterial.RequestVersionDocument, Document: empty, Profile: wire.FormatV3, Repo: "org/project", Tag: "v1", Digest: digest}
	collateral := []collateral.Entry{{ID: collateral.ConfigID, Role: collateral.RoleReferenceValues,
		Format: collateral.ConfigEndorsementV1Format, Data: []byte(`{"endorsement_ref":"test-reference"}`)}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request attestationmaterial.Request
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if r.URL.Path != "/attestation-collaterals" || !reflect.DeepEqual(request, expected) {
			t.Errorf("unexpected ATC request: %s %#v", r.URL.Path, request)
		}
		_ = json.NewEncoder(w).Encode(wire.Response{Format: wire.FormatV3, ExpiresAt: time.Now().Add(time.Hour), Collateral: collateral})
	}))
	defer server.Close()
	path := filepath.Join(t.TempDir(), "collateral-request.json")
	request, err := writeCollateralRequest(path, empty, external.Metadata, "")
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var persisted attestationmaterial.Request
	if err := json.Unmarshal(data, &persisted); err != nil || !reflect.DeepEqual(persisted, request) {
		t.Fatalf("persisted request = %#v, error = %v", persisted, err)
	}
	client, err := attestationmaterial.NewClient(server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := client.Fetch(context.Background(), persisted)
	if err != nil || !reflect.DeepEqual(got.Collateral, collateral) {
		t.Fatalf("collateral = %#v, error = %v", got.Collateral, err)
	}
}

func TestLocalCollateralRequestIncludesExactConfig(t *testing.T) {
	const runtimeVersion = "0.15.1-rc.1@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	config := []byte("# Exact bytes\r\ncvm-version: " + runtimeVersion + "\r\n")
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(configPath, config, 0600); err != nil {
		t.Fatal(err)
	}
	empty, err := document.Build(document.BuildInput{Nonce: make([]byte, document.NonceSize), CollateralFormat: wire.FormatV3}, func([64]byte) (string, []byte, error) {
		return document.SEVSNPReportV1Format, []byte("quote"), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "collateral-request.json")
	metadata := shimconfig.Metadata{ConfigSource: shimconfig.SourceLocal, Repo: "private/project", Tag: "private-revision", Digest: "private-digest"}
	request, err := writeCollateralRequest(path, empty, metadata, configPath)
	if err != nil {
		t.Fatal(err)
	}
	expected := attestationmaterial.Request{Version: attestationmaterial.RequestVersionDocument, Profile: wire.FormatV3, Document: empty, Config: config}
	if !reflect.DeepEqual(request, expected) {
		t.Fatalf("request = %#v, want %#v", request, expected)
	}
	data, err := os.ReadFile(path)
	if err != nil || strings.Contains(string(data), "private") || strings.Contains(string(data), "quote_base64") {
		t.Fatalf("unexpected collateral request: %s; error: %v", data, err)
	}
	var persisted attestationmaterial.Request
	if err := json.Unmarshal(data, &persisted); err != nil || !reflect.DeepEqual(persisted, request) {
		t.Fatalf("persisted request = %#v, error = %v", persisted, err)
	}
	if err := os.Remove(configPath); err != nil {
		t.Fatal(err)
	}
	if _, err := writeCollateralRequest(path, empty, metadata, configPath); err == nil {
		t.Fatal("missing local config accepted")
	}
}

func TestDummyAttestationSkipsHardwareAndCollateral(t *testing.T) {
	for _, tc := range []struct {
		domain string
		config shimconfig.Config
	}{
		{domain: "localhost"}, {domain: "enclave.example", config: shimconfig.Config{DummyAttestation: true}},
	} {
		doc, err := fetchCPUAttestation(tc.domain, &tc.config)
		if err != nil || len(doc) != 0 {
			t.Fatalf("dummy attestation = %s, %v", doc, err)
		}
		path := filepath.Join(t.TempDir(), "request.json")
		_, err = writeCollateralRequest(path, doc, shimconfig.Metadata{}, "")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("dummy collateral artifact exists: %v", err)
		}
	}
}
