package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tinfoilsh/encrypted-http-body-protocol/identity"
	envelope "github.com/tinfoilsh/tinfoil-go/verify/document"

	tinfoilattestation "tinfoil/internal/attestation"
	"tinfoil/internal/config"
)

func testClockAttestationHandler(t *testing.T) http.Handler {
	t.Helper()
	id, err := identity.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	registerObservabilityHandlers(mux, id.Middleware(),
		tinfoilattestation.Identity{}, 0, id, nil, staticCollateralSource{}, &config.ExternalConfig{})
	return mux
}

func TestTimedAttestationRequestRequiresUnambiguousVersionAndNonce(t *testing.T) {
	nonce := strings.Repeat("42", envelope.NonceSize)
	handler := testClockAttestationHandler(t)
	for _, query := range []string{
		"format=v4",
		"format=v4&nonce=",
		"format=v4&nonce=42",
		"format=v4&nonce=" + strings.Repeat("zz", envelope.NonceSize),
		"format=v4&nonce=" + nonce + "&nonce=" + nonce,
		"format=v5&nonce=" + nonce,
		"format=&nonce=" + nonce,
		"format=v4&format=v4&nonce=" + nonce,
	} {
		t.Run(query, func(t *testing.T) {
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/tinfoil-attestation?"+query, nil))
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestUntimedAttestationRequiresNonce(t *testing.T) {
	handler := testClockAttestationHandler(t)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, attestationPath, nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d", rec.Code)
	}
}
