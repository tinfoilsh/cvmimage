package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tinfoilsh/encrypted-http-body-protocol/identity"
	envelope "github.com/tinfoilsh/tinfoil-go/verify/document"

	tinfoilattestation "tinfoil/internal/attestation"
	"tinfoil/internal/config"
	"tinfoil/internal/trustedtime"
)

func testClockAttestationHandler(t *testing.T, readTime func() (trustedtime.Sample, error)) http.Handler {
	t.Helper()
	id, err := identity.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	registerObservabilityHandlers(mux, id.Middleware(),
		tinfoilattestation.Identity{}, 0, id, nil, staticCollateralSource{}, &config.ExternalConfig{}, readTime)
	return mux
}

func TestTimedAttestationRequestRequiresUnambiguousVersionAndNonce(t *testing.T) {
	nonce := strings.Repeat("42", envelope.NonceSize)
	handler := testClockAttestationHandler(t, func() (trustedtime.Sample, error) {
		t.Fatal("invalid request reached the clock reader")
		return trustedtime.Sample{}, nil
	})
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

func TestTimedAttestationReturns503ForUnusableClock(t *testing.T) {
	sampleTime := time.Date(2026, time.October, 1, 0, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name   string
		sample trustedtime.Sample
		err    error
	}{
		{name: "reader unavailable", sample: trustedtime.Sample{Time: sampleTime}, err: errors.New("reader unavailable")},
		{name: "zero UTC"},
		{name: "negative uncertainty", sample: trustedtime.Sample{Time: sampleTime, Uncertainty: -time.Nanosecond}},
		{name: "excess uncertainty", sample: trustedtime.Sample{Time: sampleTime, Uncertainty: trustedtime.MaxUncertainty + time.Nanosecond}},
	} {
		t.Run(test.name, func(t *testing.T) {
			reads := 0
			handler := testClockAttestationHandler(t, func() (trustedtime.Sample, error) {
				reads++
				return test.sample, test.err
			})
			rec := httptest.NewRecorder()
			url := "/.well-known/tinfoil-attestation?format=v4&nonce=" + strings.Repeat("42", envelope.NonceSize)
			handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, url, nil))
			if rec.Code != http.StatusServiceUnavailable || reads != 1 {
				t.Fatalf("status = %d, reads = %d, body = %s", rec.Code, reads, rec.Body.String())
			}
			var body errorEnvelope
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if body.Error.Code == nil || *body.Error.Code != errCodeAttestationUnavailable || body.Error.Message != errMsgClockUnavailable {
				t.Fatalf("error body = %+v", body)
			}
			if rec.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("time response can be cached")
			}
		})
	}
}

func TestUntimedRequestRequiresNonceWithoutReadingClock(t *testing.T) {
	handler := testClockAttestationHandler(t, func() (trustedtime.Sample, error) {
		t.Fatal("invalid request read the clock")
		return trustedtime.Sample{}, nil
	})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, attestationPath, nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d", rec.Code)
	}
}
