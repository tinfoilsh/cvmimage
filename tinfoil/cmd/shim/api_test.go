package main

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/tinfoilsh/encrypted-http-body-protocol/identity"
	"tinfoil/internal/config"
	"github.com/tinfoilsh/tinfoil-go/verifier/attestation"
)

func testServer(t *testing.T, paths []string, upstreamPort int) http.Handler {
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

	return NewShimServer(nil, nil, att, nil, id, nil, cfg, extCfg, nil)
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
