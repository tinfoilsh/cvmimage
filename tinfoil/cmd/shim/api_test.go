package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tinfoilsh/encrypted-http-body-protocol/identity"
	"github.com/tinfoilsh/tinfoil-go/verifier/attestation"
	tinfoilattestation "tinfoil/internal/attestation"
	"tinfoil/internal/config"
	"tinfoil/internal/key"
)

type fakeValidator struct {
	err   error
	calls []key.Request
}

func (f *fakeValidator) Validate(req key.Request) error {
	f.calls = append(f.calls, req)
	return f.err
}

func testAuthServer(t *testing.T, validator key.Validator, authenticatedEndpoints []string) http.Handler {
	t.Helper()

	id, err := identity.NewIdentity()
	if err != nil {
		t.Fatalf("creating identity: %v", err)
	}

	cfg := &config.Config{
		UpstreamPort:           9999,
		Authenticated:          true,
		Model:                  "measured-model",
		AuthenticatedEndpoints: &authenticatedEndpoints,
	}
	extCfg := &config.ExternalConfig{}
	att := &attestation.Document{
		Format: "https://tinfoil.sh/predicate/dummy/v2",
		Body:   "deadbeef",
	}

	return NewShimServer(validator, nil, att, tinfoilattestation.BodyV2{}, 0, id, nil, cfg, extCfg, "127.0.0.1:9999")
}

func testServer(t *testing.T, paths []string, upstreamPort int) http.Handler {
	t.Helper()
	return testFullServer(t, paths, upstreamPort)
}

func testFullServer(t *testing.T, paths []string, upstreamPort int) http.Handler {
	t.Helper()

	id, err := identity.NewIdentity()
	if err != nil {
		t.Fatalf("creating identity: %v", err)
	}

	cfg := &config.Config{
		UpstreamPort: upstreamPort,
		Paths:        paths,
	}
	extCfg := &config.ExternalConfig{}
	att := &attestation.Document{
		Format: "https://tinfoil.sh/predicate/dummy/v2",
		Body:   "deadbeef",
	}
	upstreamAddr := fmt.Sprintf("127.0.0.1:%d", upstreamPort)

	return NewShimServer(nil, nil, att, tinfoilattestation.BodyV2{}, 0, id, nil, cfg, extCfg, upstreamAddr)
}

func testObservabilityServer(t *testing.T, paths []string) http.Handler {
	t.Helper()

	id, err := identity.NewIdentity()
	if err != nil {
		t.Fatalf("creating identity: %v", err)
	}

	cfg := &config.Config{Paths: paths}
	extCfg := &config.ExternalConfig{}
	att := &attestation.Document{
		Format: "https://tinfoil.sh/predicate/dummy/v2",
		Body:   "deadbeef",
	}

	return NewObservabilityServer(att, tinfoilattestation.BodyV2{}, 0, id, nil, cfg, extCfg)
}

func TestPathNotAllowed_Returns404(t *testing.T) {
	handler := testServer(t, []string{"/v1/chat/completions", "/v1/models"}, 9999)

	req := httptest.NewRequest(http.MethodGet, "/booo", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", rec.Code, rec.Body.String())
	}

	var body map[string]map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if msg := body["error"]["message"]; msg != "Not found." {
		t.Errorf("expected error message %q, got %q", "Not found.", msg)
	}
	if typ := body["error"]["type"]; typ != "invalid_request_error" {
		t.Errorf("expected error type %q, got %q", "invalid_request_error", typ)
	}
}

func TestPathAllowed_ProxiesToUpstream(t *testing.T) {
	// Start a real upstream that returns 200.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"ok": "true"})
	}))
	defer upstream.Close()

	// Parse the port from the test server's listener.
	port := upstream.Listener.Addr().(*net.TCPAddr).Port

	handler := testServer(t, []string{"/v1/chat/completions"}, port)

	req := httptest.NewRequest(http.MethodGet, "/v1/chat/completions", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// EHBP middleware will reject the request (no encapsulated key), but the
	// important thing is we did NOT get a 404 — the path check let it through.
	if rec.Code == http.StatusNotFound {
		t.Fatalf("allowed path should not return 404, got: %s", rec.Body.String())
	}
}

func TestRequiresAuth(t *testing.T) {
	ptr := func(s []string) *[]string { return &s }

	tests := []struct {
		name                   string
		authenticatedEndpoints *[]string
		path                   string
		want                   bool
	}{
		// Nil (absent from config): default behaviour — only /v1/chat/completions
		{"default nil, chat completions", nil, "/v1/chat/completions", true},
		{"default nil, other path", nil, "/v1/models", false},
		{"default nil, root", nil, "/", false},

		// Empty list: no endpoints require auth
		{"empty list, chat completions", ptr([]string{}), "/v1/chat/completions", false},
		{"empty list, other path", ptr([]string{}), "/v1/models", false},

		// Custom list: only listed patterns require auth
		{"custom list, exact match", ptr([]string{"/v1/chat/completions", "/v1/embeddings"}), "/v1/chat/completions", true},
		{"custom list, second entry", ptr([]string{"/v1/chat/completions", "/v1/embeddings"}), "/v1/embeddings", true},
		{"custom list, unlisted path", ptr([]string{"/v1/chat/completions", "/v1/embeddings"}), "/v1/models", false},
		{"custom list, wildcard", ptr([]string{"/v1/*"}), "/v1/anything", true},
		{"custom list, wildcard no match", ptr([]string{"/v1/*"}), "/v2/chat", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := requiresAuth(tt.authenticatedEndpoints, tt.path)
			if got != tt.want {
				t.Errorf("requiresAuth(%v, %q) = %v, want %v", tt.authenticatedEndpoints, tt.path, got, tt.want)
			}
		})
	}
}

func TestAuthenticatedRequestUsesMeasuredModelPolicy(t *testing.T) {
	online := &fakeValidator{err: nil}
	handler := testAuthServer(t, online, []string{"/metrics"})

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer tk-admin-key")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code == http.StatusUnauthorized || rec.Code == http.StatusForbidden {
		t.Fatalf("online-accepted key should pass validation, got %d: %s", rec.Code, rec.Body.String())
	}
	if len(online.calls) != 1 {
		t.Fatalf("online validator calls = %d, want 1", len(online.calls))
	}
	if got := online.calls[0]; got.APIKey != "tk-admin-key" || got.Model != "measured-model" || got.Path != "/metrics" {
		t.Fatalf("online validation request = %+v", got)
	}
}

func TestAuthenticatedRequestFailsClosedWithoutValidator(t *testing.T) {
	handler := testAuthServer(t, nil, []string{"/v1/chat/completions"})
	req := httptest.NewRequest(http.MethodGet, "/v1/chat/completions", nil)
	req.Header.Set("Authorization", "Bearer token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("missing validator status = %d, want 503", rec.Code)
	}
}

func TestExtractBearerToken(t *testing.T) {
	tests := []struct {
		header string
		want   string
	}{
		{"Bearer sk-test", "sk-test"},
		{"bearer sk-test", "sk-test"},
		{"BEARER   sk-test  ", "sk-test"},
		{"Token sk-test", ""},
		{"Bearer", ""},
		{"", ""},
	}

	for _, tt := range tests {
		if got := extractBearerToken(tt.header); got != tt.want {
			t.Errorf("extractBearerToken(%q) = %q, want %q", tt.header, got, tt.want)
		}
	}
}

func TestRequestedHost(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "https://realtime-model.model.example.com/v1/realtime", nil)
	req.Host = "Realtime-Model.Model.Example.Com:443"
	if got := requestedHost(req); got != "realtime-model.model.example.com" {
		t.Fatalf("requestedHost() = %q", got)
	}
}

func TestWriteValidationFailureDoesNotLeakInternalError(t *testing.T) {
	err := errors.New("control-plane details")
	rec := httptest.NewRecorder()

	writeValidationFailure(rec, err)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d: %s", rec.Code, http.StatusInternalServerError, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), err.Error()) {
		t.Fatalf("validation error leaked raw error: %q", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), errMsgServerError) {
		t.Fatalf("expected generic server error, got: %q", rec.Body.String())
	}
}

func TestRequiresNVSwitchEvidence(t *testing.T) {
	evidence := func(arches ...string) *tinfoilattestation.GPUEvidenceCollection {
		collection := &tinfoilattestation.GPUEvidenceCollection{}
		for _, arch := range arches {
			collection.Evidences = append(collection.Evidences, tinfoilattestation.GPUEvidence{Arch: arch})
		}
		return collection
	}

	tests := []struct {
		name         string
		expectedGPUs int
		evidence     *tinfoilattestation.GPUEvidenceCollection
		want         bool
	}{
		{"single GPU never requires switch evidence", 1, evidence(tinfoilattestation.GPUArchHopper), false},
		{"nil evidence does not require switch evidence", 8, nil, false},
		{"blackwell 8 GPU skips switch evidence", 8, evidence(tinfoilattestation.GPUArchBlackwell), false},
		{"hopper 8 GPU requires switch evidence", 8, evidence(tinfoilattestation.GPUArchHopper), true},
		{"hopper non-8 GPU skips switch evidence", 4, evidence(tinfoilattestation.GPUArchHopper), false},
		{"unknown 8 GPU skips switch evidence", 8, evidence("UNKNOWN_123"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := requiresNVSwitchEvidence(tt.expectedGPUs, tt.evidence); got != tt.want {
				t.Fatalf("requiresNVSwitchEvidence(%d, %+v) = %v, want %v", tt.expectedGPUs, tt.evidence, got, tt.want)
			}
		})
	}
}

func TestNoPathsConfigured_AllPathsAllowed(t *testing.T) {
	handler := testServer(t, nil, 9999)

	req := httptest.NewRequest(http.MethodGet, "/anything/goes", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// With no paths configured, the request should pass through the path check.
	// It will hit the EHBP middleware, which is fine — just verify it's not 404.
	if rec.Code == http.StatusNotFound {
		t.Fatalf("with no paths configured, should not return 404, got: %s", rec.Body.String())
	}
}

func TestObservabilityServer_WorkloadReturns503BeforeReady(t *testing.T) {
	handler := testObservabilityServer(t, nil)

	req := httptest.NewRequest(http.MethodGet, "/v1/chat/completions", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 before proxy ready, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "Workload proxy is not ready.") {
		t.Fatalf("expected proxy readiness error, got: %s", rec.Body.String())
	}
}

func TestObservabilityServer_WellKnownEndpointsBypassProxyReadiness(t *testing.T) {
	handler := testObservabilityServer(t, nil)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/tinfoil-certificate", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code == http.StatusServiceUnavailable && strings.Contains(rec.Body.String(), "Workload proxy is not ready.") {
		t.Fatalf("well-known endpoint should bypass proxy readiness gate: %s", rec.Body.String())
	}
}

func TestFullServer_WorkloadReachesProxyPath(t *testing.T) {
	handler := testFullServer(t, nil, 9999)

	req := httptest.NewRequest(http.MethodGet, "/v1/chat/completions", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code == http.StatusServiceUnavailable && strings.Contains(rec.Body.String(), "Workload proxy is not ready.") {
		t.Fatalf("ready proxy gate should not block workload path: %s", rec.Body.String())
	}
}

func TestRewriteUpstreamRequestStripsCallerIdentity(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "https://attacker.example/v1/chat/completions", nil)
	request.Host = "attacker.example"
	for header, value := range map[string]string{
		"Authorization":         "Bearer workload-secret",
		"Proxy-Authorization":   "Basic proxy-secret",
		"Forwarded":             `for=192.0.2.1;host=attacker.example;proto=http`,
		"X-Forwarded-For":       "192.0.2.1",
		"X-Forwarded-Host":      "attacker.example",
		"X-Forwarded-Proto":     "http",
		"X-Real-IP":             "192.0.2.1",
		"Ehbp-Encapsulated-Key": "ciphertext",
		"Tinfoil-Authenticated": "true",
		"Content-Type":          "application/json",
	} {
		request.Header.Set(header, value)
	}

	rewriteUpstreamRequest(request)

	if request.Host != "localhost" {
		t.Fatalf("Host = %q, want localhost", request.Host)
	}
	for _, header := range []string{"Authorization", "Proxy-Authorization", "X-Forwarded-For", "X-Real-IP", "Ehbp-Encapsulated-Key", "Tinfoil-Authenticated"} {
		if value := request.Header.Get(header); value != "" {
			t.Fatalf("%s survived with value %q", header, value)
		}
	}
	if got := request.Header.Get("Forwarded"); got != `host="localhost";proto=https` {
		t.Fatalf("Forwarded = %q", got)
	}
	if got := request.Header.Get("X-Forwarded-Host"); got != "localhost" {
		t.Fatalf("X-Forwarded-Host = %q", got)
	}
	if got := request.Header.Get("X-Forwarded-Proto"); got != "https" {
		t.Fatalf("X-Forwarded-Proto = %q", got)
	}
	if got := request.Header.Get("Content-Type"); got != "application/json" {
		t.Fatalf("ordinary header changed: %q", got)
	}
}
