package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tinfoilsh/encrypted-http-body-protocol/identity"
	envelope "github.com/tinfoilsh/tinfoil-go/document"
	"github.com/tinfoilsh/tinfoil-go/document/collateral"

	tinfoilattestation "tinfoil/internal/attestation"
	"tinfoil/internal/config"
	"tinfoil/internal/legacy"
)

type staticCollateralSource []collateral.Entry

func (s staticCollateralSource) Current(context.Context) ([]collateral.Entry, error) {
	return s, nil
}

type errorCollateralSource struct{}

func (errorCollateralSource) Current(context.Context) ([]collateral.Entry, error) {
	return nil, errors.New("expired")
}

func testFullServer(t *testing.T, upstreamPort int) http.Handler {
	t.Helper()

	id, err := identity.NewIdentity()
	if err != nil {
		t.Fatalf("creating identity: %v", err)
	}

	extCfg := &config.ExternalConfig{}
	att := &legacy.Document{
		Format: "https://tinfoil.sh/predicate/dummy/v2",
		Body:   "deadbeef",
	}
	upstreamAddr := fmt.Sprintf("127.0.0.1:%d", upstreamPort)
	return NewShimServer(att, tinfoilattestation.Identity{}, 0, id, nil, staticCollateralSource{}, extCfg, upstreamAddr, nil)
}

func testObservabilityServer(t *testing.T) http.Handler {
	t.Helper()

	id, err := identity.NewIdentity()
	if err != nil {
		t.Fatalf("creating identity: %v", err)
	}

	extCfg := &config.ExternalConfig{}
	att := &legacy.Document{
		Format: "https://tinfoil.sh/predicate/dummy/v2",
		Body:   "deadbeef",
	}
	return NewObservabilityServer(att, tinfoilattestation.Identity{}, 0, id, nil, staticCollateralSource{}, extCfg)
}

func TestV3AttestationReturns503WhenCollateralExpired(t *testing.T) {
	id, err := identity.NewIdentity()
	if err != nil {
		t.Fatalf("creating identity: %v", err)
	}
	handler := NewObservabilityServer(
		&legacy.Document{Format: legacy.DummyV2, Body: "deadbeef"},
		tinfoilattestation.Identity{},
		0,
		id,
		nil,
		errorCollateralSource{},
		&config.ExternalConfig{},
	)
	for _, path := range []string{attestationPath, attestationV3Path, attestationV3Path + "/"} {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, path+"?nonce="+strings.Repeat("00", envelope.NonceSize), nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusServiceUnavailable {
				t.Fatalf("status = %d, want %d: %s", rec.Code, http.StatusServiceUnavailable, rec.Body.String())
			}
		})
	}
}

func TestAttestationEndpointCompatibility(t *testing.T) {
	for name, handler := range map[string]http.Handler{
		"shim":          testFullServer(t, 9999),
		"observability": testObservabilityServer(t),
	} {
		t.Run(name, func(t *testing.T) {
			for _, query := range []string{"", "?nonce=", "?cache=1"} {
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, attestationPath+query, nil))
				if rec.Code != http.StatusOK {
					t.Fatalf("legacy status = %d: %s", rec.Code, rec.Body.String())
				}
				var document legacy.Document
				if err := json.Unmarshal(rec.Body.Bytes(), &document); err != nil {
					t.Fatal(err)
				}
				if document.Format != legacy.DummyV2 || document.Body != "deadbeef" || rec.Header().Get(attestationFormatHeader) != string(document.Format) {
					t.Fatalf("legacy response changed: headers=%v body=%s", rec.Header(), rec.Body.String())
				}
			}
			for _, path := range []string{attestationV3Path, attestationV3Path + "/"} {
				for _, query := range []string{"", "?nonce=", "?nonce=ab", "?nonce=" + strings.Repeat("zz", envelope.NonceSize), "?nonce=" + strings.Repeat("00", envelope.NonceSize) + "&nonce=ab", "?nonce=ab&%zz=value", "?nonce=" + strings.Repeat("00", envelope.NonceSize) + "&cache=1"} {
					rec := httptest.NewRecorder()
					handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path+query, nil))
					if rec.Code != http.StatusBadRequest {
						t.Errorf("%s%s: status = %d, want %d: %s", path, query, rec.Code, http.StatusBadRequest, rec.Body.String())
					}
				}
			}
			for _, path := range []string{attestationPath + "/v4", attestationV3Path + "/extra"} {
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
				if rec.Code != http.StatusNotFound {
					t.Errorf("%s: status = %d, want %d", path, rec.Code, http.StatusNotFound)
				}
			}
		})
	}
}

func TestObservabilityServer_WorkloadReturns503BeforeReady(t *testing.T) {
	handler := testObservabilityServer(t)

	req := httptest.NewRequest(http.MethodGet, "/v1/chat/completions", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 before proxy ready, got %d: %s", rec.Code, rec.Body.String())
	}
	var envelope errorEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("body is not an error envelope: %s", rec.Body.String())
	}
	if envelope.Error.Type != errTypeServiceUnavailable || envelope.Error.Code == nil || *envelope.Error.Code != errCodeServiceStarting {
		t.Fatalf("expected service_starting error, got: %s", rec.Body.String())
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Fatal("pending boot must send Retry-After")
	}
}

func TestObservabilityServer_WellKnownEndpointsBypassProxyReadiness(t *testing.T) {
	handler := testObservabilityServer(t)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/tinfoil-certificate", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code == http.StatusServiceUnavailable && strings.Contains(rec.Body.String(), errCodeServiceStarting) {
		t.Fatalf("well-known endpoint should bypass proxy readiness gate: %s", rec.Body.String())
	}
}

func TestFullServer_WorkloadReachesProxyPath(t *testing.T) {
	handler := testFullServer(t, 9999)

	req := httptest.NewRequest(http.MethodGet, "/v1/chat/completions", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code == http.StatusServiceUnavailable && strings.Contains(rec.Body.String(), errCodeServiceStarting) {
		t.Fatalf("ready proxy gate should not block workload path: %s", rec.Body.String())
	}
}

func TestWriteAPIErrorEmitsFourFieldEnvelope(t *testing.T) {
	rec := httptest.NewRecorder()
	writeAPIError(rec, errServer)

	var raw map[string]map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	inner := raw["error"]
	for _, key := range []string{"message", "type", "param", "code"} {
		if _, ok := inner[key]; !ok {
			t.Errorf("missing %q in %v", key, inner)
		}
	}
	if len(inner) != 4 {
		t.Fatalf("envelope has %d fields, want 4: %v", len(inner), inner)
	}
	if inner["code"] != nil || inner["param"] != nil {
		t.Fatalf("unset code/param must be null: %v", inner)
	}
}
