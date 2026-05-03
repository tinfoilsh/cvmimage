package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tinfoilsh/encrypted-http-body-protocol/identity"
	tinfoilattestation "tinfoil/internal/attestation"
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

	return NewShimServer(nil, nil, att, tinfoilattestation.BodyV2{}, 0, id, nil, cfg, extCfg)
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

func TestAuthPolicy(t *testing.T) {
	ptr := func(s []config.AuthenticatedEndpoint) *[]config.AuthenticatedEndpoint { return &s }

	tests := []struct {
		name           string
		endpoints      *[]config.AuthenticatedEndpoint
		path           string
		wantRequired   bool
		wantValidateIP bool
	}{
		// Nil (absent from config): default behaviour — only /v1/chat/completions, key-only
		{"default nil, chat completions", nil, "/v1/chat/completions", true, false},
		{"default nil, other path", nil, "/v1/models", false, false},
		{"default nil, root", nil, "/", false, false},

		// Empty list: no endpoints require auth
		{"empty list, chat completions", ptr([]config.AuthenticatedEndpoint{}), "/v1/chat/completions", false, false},
		{"empty list, other path", ptr([]config.AuthenticatedEndpoint{}), "/v1/models", false, false},

		// Custom list: only listed patterns require auth, ValidateIP is per entry
		{
			"custom list, exact match key-only",
			ptr([]config.AuthenticatedEndpoint{{Path: "/v1/chat/completions"}, {Path: "/v1/embeddings"}}),
			"/v1/chat/completions", true, false,
		},
		{
			"custom list, exact match validate-ip",
			ptr([]config.AuthenticatedEndpoint{{Path: "/v1/chat/completions", ValidateIP: true}, {Path: "/v1/embeddings"}}),
			"/v1/chat/completions", true, true,
		},
		{
			"custom list, second entry without ip",
			ptr([]config.AuthenticatedEndpoint{{Path: "/v1/chat/completions", ValidateIP: true}, {Path: "/v1/embeddings"}}),
			"/v1/embeddings", true, false,
		},
		{
			"custom list, unlisted path",
			ptr([]config.AuthenticatedEndpoint{{Path: "/v1/chat/completions"}, {Path: "/v1/embeddings"}}),
			"/v1/models", false, false,
		},
		{
			"custom list, wildcard match",
			ptr([]config.AuthenticatedEndpoint{{Path: "/v1/*", ValidateIP: true}}),
			"/v1/anything", true, true,
		},
		{
			"custom list, wildcard no match",
			ptr([]config.AuthenticatedEndpoint{{Path: "/v1/*", ValidateIP: true}}),
			"/v2/chat", false, false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotRequired, gotValidateIP := authPolicy(tt.endpoints, tt.path)
			if gotRequired != tt.wantRequired || gotValidateIP != tt.wantValidateIP {
				t.Errorf("authPolicy(%v, %q) = (%v, %v), want (%v, %v)",
					tt.endpoints, tt.path, gotRequired, gotValidateIP, tt.wantRequired, tt.wantValidateIP)
			}
		})
	}
}

func TestExtractModel(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{"chat completion with model", `{"model":"llama-3","messages":[]}`, "llama-3"},
		{"model only", `{"model":"mixtral"}`, "mixtral"},
		{"missing model field", `{"messages":[]}`, ""},
		{"empty body", ``, ""},
		{"non-json body", `not json at all`, ""},
		{"model after other fields", `{"messages":[],"model":"gpt-oss-120b"}`, "gpt-oss-120b"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(tt.body))
			got := extractModel(req)
			if got != tt.want {
				t.Errorf("extractModel(%q) = %q, want %q", tt.body, got, tt.want)
			}

			// Body must be fully readable after extraction.
			restored, err := io.ReadAll(req.Body)
			if err != nil {
				t.Fatalf("reading restored body: %v", err)
			}
			if !bytes.Equal(restored, []byte(tt.body)) {
				t.Errorf("body not preserved: got %q, want %q", restored, tt.body)
			}
		})
	}
}

func TestExtractModel_NilBody(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	req.Body = nil
	if got := extractModel(req); got != "" {
		t.Errorf("expected empty model for nil body, got %q", got)
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
