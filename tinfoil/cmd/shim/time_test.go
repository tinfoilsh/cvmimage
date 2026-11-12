package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"tinfoil/internal/config"
	"tinfoil/internal/trustedtime"
)

func TestTrustedTimeGateClosesAfterSynchronizationLoss(t *testing.T) {
	var clockErr error
	requests := 0
	handler := checkTrustedTime(&config.Config{}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.WriteHeader(http.StatusNoContent)
	}), func() (trustedtime.Sample, error) {
		return trustedtime.Sample{}, clockErr
	})
	for _, test := range []struct {
		err      error
		status   int
		requests int
	}{
		{nil, http.StatusNoContent, 1},
		{errors.New("checkpoint expired"), http.StatusServiceUnavailable, 1},
		{errors.New("clock stepped"), http.StatusServiceUnavailable, 1},
	} {
		clockErr = test.err
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))
		if response.Code != test.status || requests != test.requests {
			t.Fatalf("status=%d forwarded=%d; want %d, %d", response.Code, requests, test.status, test.requests)
		}
	}
}

func TestTrustedTimeFailurePreservesCORSPolicy(t *testing.T) {
	const allowedOrigin = "https://allowed.example"
	handler := checkTrustedTime(&config.Config{OriginDomains: []string{allowedOrigin}}, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("forwarded a request without trusted time")
	}), func() (trustedtime.Sample, error) {
		return trustedtime.Sample{}, errors.New("checkpoint expired")
	})
	for _, test := range []struct {
		method string
		origin string
		status int
		allow  string
	}{
		{http.MethodGet, allowedOrigin, http.StatusServiceUnavailable, allowedOrigin},
		{http.MethodOptions, allowedOrigin, http.StatusNoContent, allowedOrigin},
		{http.MethodGet, "https://denied.example", http.StatusForbidden, ""},
		{http.MethodOptions, "https://denied.example", http.StatusForbidden, ""},
	} {
		request := httptest.NewRequest(test.method, "/", nil)
		request.Header.Set("Origin", test.origin)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != test.status || response.Header().Get("Access-Control-Allow-Origin") != test.allow {
			t.Errorf("%s %s: status=%d allow-origin=%q", test.method, test.origin, response.Code, response.Header().Get("Access-Control-Allow-Origin"))
		}
	}
}

func TestTrustedTimeGatePreservesDiagnosticsAndRejectsOtherRequests(t *testing.T) {
	forwarded := 0
	handler := checkTrustedTime(&config.Config{}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded++
		w.WriteHeader(http.StatusNoContent)
	}), func() (trustedtime.Sample, error) {
		return trustedtime.Sample{}, errors.New("checkpoint expired")
	})
	diagnosticPaths := []string{bootStagesPath, metricsPath, tinfoilMetricsPath, containersPath}
	for _, path := range diagnosticPaths {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusNoContent {
			t.Fatalf("diagnostics %s = %d", path, response.Code)
		}
	}
	if forwarded != len(diagnosticPaths) {
		t.Fatalf("forwarded diagnostics = %d", forwarded)
	}
	for _, test := range []struct{ method, path string }{
		{http.MethodGet, attestationPath},
		{http.MethodPost, "/v1/chat/completions"},
		{http.MethodPost, bootStagesPath},
		{http.MethodGet, "/.well-known/%74infoil-boot-stages"},
	} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(test.method, test.path, nil))
		var body errorEnvelope
		if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if response.Code != http.StatusServiceUnavailable || body.Error.Type != errTypeServiceUnavailable || body.Error.Code == nil || *body.Error.Code != errCodeTrustedTimeUnavailable {
			t.Fatalf("%s %s = %d %s", test.method, test.path, response.Code, response.Body.String())
		}
	}
	if forwarded != len(diagnosticPaths) {
		t.Fatal("forwarded a request requiring trusted time")
	}
}
