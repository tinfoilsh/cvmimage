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
	for _, format := range []string{collateral.ConfigEndorsementV1Format, collateral.ConfigEndorsementV2Format} {
		t.Run(format+" public", func(t *testing.T) { testConfigCollateralRequest(t, format, false) })
		if format == collateral.ConfigEndorsementV2Format {
			t.Run(format+" private", func(t *testing.T) { testConfigCollateralRequest(t, format, true) })
		}
	}
}

func testConfigCollateralRequest(t *testing.T, format string, private bool) {
	t.Helper()
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
	proof := []byte(fmt.Sprintf(`{"endorsement_ref":"sha256:%s","config_base64":"Y29uZmln","sigstore_bundle":{}}`, digest))
	if private {
		proof = []byte(fmt.Sprintf(`{"endorsement_ref":"sha256:%s","sigstore_bundle":{},"scope":{"certificate_der":"bGVhZg==","issuer_der":"cm9vdA==","issuance_bundle":{"proof":"issuance"}}}`, digest))
	}
	entries := []collateral.Entry{{ID: collateral.ConfigID, Role: collateral.RoleReferenceValues,
		Format: format, Data: proof}}
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
		_ = json.NewEncoder(w).Encode(wire.Response{Format: wire.FormatV3, ExpiresAt: time.Now().Add(time.Hour), Collateral: entries})
	}))
	defer server.Close()
	path := filepath.Join(t.TempDir(), "collateral-request.json")
	configPath := filepath.Join(t.TempDir(), "private.yaml")
	if err := os.WriteFile(configPath, []byte("# private audit bytes\n"), 0600); err != nil {
		t.Fatal(err)
	}
	request, err := writeCollateralRequest(path, empty, external.Metadata, configPath)
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
	if strings.Contains(string(data), "config_base64") {
		t.Fatal("registry collateral request disclosed config bytes")
	}
	client, err := attestationmaterial.NewClient(server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := client.Fetch(context.Background(), persisted)
	if err != nil || !reflect.DeepEqual(got.Collateral, entries) {
		t.Fatalf("collateral = %#v, error = %v", got.Collateral, err)
	}
	nonce := make([]byte, document.NonceSize)
	assembled, err := document.Build(document.BuildInput{Nonce: nonce, CollateralFormat: got.Format, Collateral: got.Collateral}, func([64]byte) (string, []byte, error) {
		return document.SEVSNPReportV1Format, []byte("quote"), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := document.Parse(assembled, nonce)
	if err != nil {
		t.Fatal(err)
	}
	endorsement, err := parsed.ConfigEndorsement()
	if err != nil || endorsement.Reference != "sha256:"+digest {
		t.Fatalf("assembled endorsement = %#v, error = %v", endorsement, err)
	}
	if !private && string(endorsement.Config) != "config" {
		t.Fatalf("assembled public endorsement lost its config bytes: %#v", endorsement)
	}
	if private {
		var expected struct {
			Scope *collateral.ScopeCertificate `json:"scope"`
		}
		if err := json.Unmarshal(proof, &expected); err != nil {
			t.Fatal(err)
		}
		if len(endorsement.Config) != 0 || !reflect.DeepEqual(expected.Scope, endorsement.Scope) {
			t.Fatalf("assembled private endorsement lost its scope or exposed config bytes: %#v", endorsement)
		}
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
