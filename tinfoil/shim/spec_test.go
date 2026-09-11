package shim

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tinfoilsh/encrypted-http-body-protocol/identity"
	"github.com/tinfoilsh/tinfoil-go/verifier/envelope"
	"tinfoil/internal/attestation"
	"tinfoil/internal/config"
	"tinfoil/internal/legacy"
)

func TestObservabilityUsesDeclaredProvidersInBothPhases(t *testing.T) {
	for _, full := range []bool{false, true} {
		id, err := identity.NewIdentity()
		if err != nil {
			t.Fatal(err)
		}
		calls := 0
		observability := Observability{
			DeviceEvidence: func(nonce [32]byte) ([]envelope.DeviceEvidenceItem, error) {
				calls++
				for _, b := range nonce {
					if b != 0x42 {
						t.Fatalf("nonce changed: %x", nonce)
					}
				}
				return nil, errors.New("test evidence unavailable")
			},
			EvidenceUnavailable: "Configured evidence failure",
			Handlers: map[string]http.Handler{
				"/.well-known/workload-status": http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusAccepted)
				}),
			},
		}
		document := &legacy.Document{Format: legacy.DummyV2}
		cfg := &config.Config{}
		var handler http.Handler
		if full {
			handler = NewShimServer(nil, nil, document, attestation.BodyV2{}, id, nil, nil, cfg, "", "127.0.0.1:1", nil, observability)
		} else {
			handler = NewObservabilityServer(document, attestation.BodyV2{}, id, nil, nil, cfg, observability)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/tinfoil-attestation?nonce="+strings.Repeat("42", 32), nil))
		if calls != 1 || rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), "Configured evidence failure") {
			t.Fatalf("full=%t: calls=%d status=%d", full, calls, rec.Code)
		}
		rec = httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/workload-status", nil))
		if rec.Code != http.StatusAccepted {
			t.Fatalf("full=%t: declared route status=%d", full, rec.Code)
		}
	}
}
