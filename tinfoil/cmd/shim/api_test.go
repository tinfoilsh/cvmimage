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
	wire "github.com/tinfoilsh/tinfoil-go/collaterals"
	envelope "github.com/tinfoilsh/tinfoil-go/verify/document"

	tinfoilattestation "tinfoil/internal/attestation"
	"tinfoil/internal/config"
)

type staticCollateralSource wire.Response

func (s staticCollateralSource) Current(context.Context) (wire.Response, error) {
	return wire.Response(s), nil
}

type errorCollateralSource struct{}

func (errorCollateralSource) Current(context.Context) (wire.Response, error) {
	return wire.Response{}, errors.New("expired")
}

func testFullServer(t *testing.T, upstreamPort int) http.Handler {
	t.Helper()

	id, err := identity.NewIdentity()
	if err != nil {
		t.Fatalf("creating identity: %v", err)
	}

	extCfg := &config.ExternalConfig{}
	upstreamAddr := fmt.Sprintf("127.0.0.1:%d", upstreamPort)
	return NewShimServer(tinfoilattestation.Identity{}, 0, id, nil, staticCollateralSource{}, extCfg, upstreamAddr, nil)
}

func testObservabilityServer(t *testing.T) http.Handler {
	t.Helper()

	id, err := identity.NewIdentity()
	if err != nil {
		t.Fatalf("creating identity: %v", err)
	}

	extCfg := &config.ExternalConfig{}
	return NewObservabilityServer(tinfoilattestation.Identity{}, 0, id, nil, staticCollateralSource{}, extCfg)
}

func TestV3AttestationReturns503WhenCollateralExpired(t *testing.T) {
	id, err := identity.NewIdentity()
	if err != nil {
		t.Fatalf("creating identity: %v", err)
	}
	handler := NewObservabilityServer(
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

func TestAttestationRequiresNonce(t *testing.T) {
	for name, handler := range map[string]http.Handler{
		"shim":          testFullServer(t, 9999),
		"observability": testObservabilityServer(t),
	} {
		t.Run(name, func(t *testing.T) {
			for _, path := range []string{attestationPath, attestationV3Path, attestationV3Path + "/"} {
				for _, query := range []string{"", "?nonce=", "?cache=1", "?nonce=ab", "?nonce=" + strings.Repeat("00", envelope.NonceSize+1), "?nonce=" + strings.Repeat("zz", envelope.NonceSize), "?nonce=" + strings.Repeat("00", envelope.NonceSize) + "&nonce=ab", "?nonce=ab&%zz=value", "?nonce=" + strings.Repeat("00", envelope.NonceSize) + "&cache=1"} {
					rec := httptest.NewRecorder()
					handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path+query, nil))
					if rec.Code != http.StatusBadRequest {
						t.Errorf("%s%s: status = %d, want %d: %s", path, query, rec.Code, http.StatusBadRequest, rec.Body.String())
					}
					if got := rec.Header().Get(attestationFormatHeader); got != envelope.AttestationV3Format {
						t.Errorf("%s%s: attestation format = %q, want %q", path, query, got, envelope.AttestationV3Format)
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
