package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tinfoilsh/encrypted-http-body-protocol/identity"
	"github.com/tinfoilsh/tinfoil-go/verifier/envelope"
	"golang.org/x/time/rate"

	tinfoilattestation "tinfoil/internal/attestation"
	"tinfoil/internal/config"
	"tinfoil/internal/key"
	"tinfoil/internal/legacy"
)

type staticCollateralSource []envelope.CollateralEntry

func (s staticCollateralSource) Current(context.Context) ([]envelope.CollateralEntry, error) {
	return s, nil
}

type errorCollateralSource struct{}

func (errorCollateralSource) Current(context.Context) ([]envelope.CollateralEntry, error) {
	return nil, errors.New("expired")
}

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
		AuthenticatedEndpoints: &authenticatedEndpoints,
	}
	extCfg := &config.ExternalConfig{}
	att := &legacy.Document{
		Format: "https://tinfoil.sh/predicate/dummy/v2",
		Body:   "deadbeef",
	}

	return NewShimServer(validator, nil, att, tinfoilattestation.BodyV2{}, 0, id, nil, nil, cfg, extCfg, "127.0.0.1:9999", nil)
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
	att := &legacy.Document{
		Format: "https://tinfoil.sh/predicate/dummy/v2",
		Body:   "deadbeef",
	}
	upstreamAddr := fmt.Sprintf("127.0.0.1:%d", upstreamPort)
	return NewShimServer(nil, nil, att, tinfoilattestation.BodyV2{}, 0, id, nil, staticCollateralSource{}, cfg, extCfg, upstreamAddr, nil)
}

func testObservabilityServer(t *testing.T, paths []string) http.Handler {
	t.Helper()

	id, err := identity.NewIdentity()
	if err != nil {
		t.Fatalf("creating identity: %v", err)
	}

	cfg := &config.Config{Paths: paths}
	extCfg := &config.ExternalConfig{}
	att := &legacy.Document{
		Format: "https://tinfoil.sh/predicate/dummy/v2",
		Body:   "deadbeef",
	}
	return NewObservabilityServer(att, tinfoilattestation.BodyV2{}, 0, id, nil, staticCollateralSource{}, cfg, extCfg)
}

func TestV3AttestationReturns503WhenCollateralExpired(t *testing.T) {
	id, err := identity.NewIdentity()
	if err != nil {
		t.Fatalf("creating identity: %v", err)
	}
	handler := NewObservabilityServer(
		&legacy.Document{Format: legacy.DummyV2, Body: "deadbeef"},
		tinfoilattestation.BodyV2{},
		0,
		id,
		nil,
		errorCollateralSource{},
		&config.Config{},
		&config.ExternalConfig{},
	)
	req := httptest.NewRequest(http.MethodGet, "/.well-known/tinfoil-attestation?nonce="+strings.Repeat("00", 32), nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d: %s", rec.Code, http.StatusServiceUnavailable, rec.Body.String())
	}
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

func TestMetricsValidation_JWTGoesOnline(t *testing.T) {
	// The local JWT leg accepts any inference-scoped token; /metrics must not
	// be satisfiable by it, so the online validator's verdict is final.
	jwt := &fakeValidator{err: nil}
	online := &fakeValidator{err: &key.ValidationError{StatusCode: http.StatusForbidden}}
	validator := &metricsValidator{online: online, chain: key.NewChain(jwt, online)}

	handler := testAuthServer(t, validator, []string{"/metrics", "/v1/chat/completions"})

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer eyJhbGciOiJFZERTQSJ9.e30.sig")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 from online validator, got %d: %s", rec.Code, rec.Body.String())
	}
	if len(jwt.calls) != 0 {
		t.Fatalf("local JWT validator must not be consulted for /metrics, calls=%d", len(jwt.calls))
	}
	if len(online.calls) != 1 || online.calls[0].Path != "/metrics" {
		t.Fatalf("online validator calls = %+v, want one call with path /metrics", online.calls)
	}
}

func TestMetricsValidation_OpaqueKeyGoesOnline(t *testing.T) {
	jwt := &fakeValidator{err: key.ErrUnsupportedToken}
	online := &fakeValidator{err: nil}
	validator := &metricsValidator{online: online, chain: key.NewChain(jwt, online)}

	handler := testAuthServer(t, validator, []string{"/metrics"})

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
	if got := online.calls[0]; got.APIKey != "tk-admin-key" || got.Path != "/metrics" {
		t.Fatalf("online validation request = %+v", got)
	}
}

func TestMetricsValidation_OtherPathsKeepChain(t *testing.T) {
	jwt := &fakeValidator{err: nil}
	online := &fakeValidator{err: &key.ValidationError{StatusCode: http.StatusForbidden}}
	validator := &metricsValidator{online: online, chain: key.NewChain(jwt, online)}

	handler := testAuthServer(t, validator, []string{"/metrics", "/v1/chat/completions"})

	req := httptest.NewRequest(http.MethodGet, "/v1/chat/completions", nil)
	req.Header.Set("Authorization", "Bearer eyJhbGciOiJFZERTQSJ9.e30.sig")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code == http.StatusUnauthorized || rec.Code == http.StatusForbidden {
		t.Fatalf("locally-validated JWT should pass on inference paths, got %d: %s", rec.Code, rec.Body.String())
	}
	if len(jwt.calls) != 1 {
		t.Fatalf("jwt validator calls = %d, want 1", len(jwt.calls))
	}
	if len(online.calls) != 0 {
		t.Fatalf("online validator must not be consulted when JWT leg succeeds, calls=%d", len(online.calls))
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
	handler := testObservabilityServer(t, nil)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/tinfoil-certificate", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code == http.StatusServiceUnavailable && strings.Contains(rec.Body.String(), errCodeServiceStarting) {
		t.Fatalf("well-known endpoint should bypass proxy readiness gate: %s", rec.Body.String())
	}
}

func TestFullServer_WorkloadReachesProxyPath(t *testing.T) {
	handler := testFullServer(t, nil, 9999)

	req := httptest.NewRequest(http.MethodGet, "/v1/chat/completions", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code == http.StatusServiceUnavailable && strings.Contains(rec.Body.String(), errCodeServiceStarting) {
		t.Fatalf("ready proxy gate should not block workload path: %s", rec.Body.String())
	}
}

func decodeErrorEnvelope(t *testing.T, rec *httptest.ResponseRecorder) errorBody {
	t.Helper()
	var envelope errorEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("body is not an error envelope: %s", rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type = %q", ct)
	}
	return envelope.Error
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

// TestValidationFailureDistinguishesForbiddenFromUnauthorized pins that a
// credential the validator accepted but refused for lack of permission is
// not reported as an incorrect key, which would send the user off to
// regenerate a key that was fine.
func TestValidationFailureDistinguishesForbiddenFromUnauthorized(t *testing.T) {
	cases := []struct {
		name       string
		status     int
		wantStatus int
		wantCode   string
		wantType   string
	}{
		{"unauthorized is invalid key", http.StatusUnauthorized, http.StatusUnauthorized, errCodeInvalidAPIKey, errTypeInvalidRequest},
		{"forbidden is insufficient permissions", http.StatusForbidden, http.StatusForbidden, errCodeInsufficientPermissions, errTypeInvalidRequest},
		{"payment required maps to 429 quota", http.StatusPaymentRequired, http.StatusTooManyRequests, errCodeInsufficientQuota, errTypeInsufficientQuota},
		{"too many requests is rate limit", http.StatusTooManyRequests, http.StatusTooManyRequests, errCodeRateLimitExceeded, errTypeRateLimit},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			writeValidationFailure(rec, &key.ValidationError{StatusCode: tc.status})
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
			body := decodeErrorEnvelope(t, rec)
			if body.Code == nil || *body.Code != tc.wantCode || body.Type != tc.wantType {
				t.Fatalf("code/type = %v/%s, want %s/%s", body.Code, body.Type, tc.wantCode, tc.wantType)
			}
		})
	}
}

func TestMissingAPIKeyReportsOpenAICode(t *testing.T) {
	handler := testAuthServer(t, &fakeValidator{}, []string{"/v1/chat/completions"})
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader("{}"))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401: %s", rec.Code, rec.Body.String())
	}
	body := decodeErrorEnvelope(t, rec)
	if body.Code == nil || *body.Code != errCodeMissingAPIKey {
		t.Fatalf("code = %v, want %s", body.Code, errCodeMissingAPIKey)
	}
}

// TestLocalRateLimitSendsRetryAfter pins that the shim's own token bucket
// rejects with rate_limit_error and a Retry-After the client can honor.
func TestLocalRateLimitSendsRetryAfter(t *testing.T) {
	id, err := identity.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{UpstreamPort: 9999}
	att := &legacy.Document{Format: "https://tinfoil.sh/predicate/dummy/v2", Body: "deadbeef"}
	// One token per minute with a burst of one: the second request is over budget.
	limiter := NewRateLimiter(1.0/60, 1)
	handler := NewShimServer(nil, limiter, att, tinfoilattestation.BodyV2{}, 0, id, nil, nil, cfg, &config.ExternalConfig{}, "127.0.0.1:9999", nil)

	send := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader("{}"))
		req.Header.Set("Authorization", "Bearer key-1")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}
	if first := send(); first.Code == http.StatusTooManyRequests {
		t.Fatalf("first request should be admitted, got 429: %s", first.Body.String())
	}
	second := send()
	if second.Code != http.StatusTooManyRequests {
		t.Fatalf("second request status = %d, want 429: %s", second.Code, second.Body.String())
	}
	body := decodeErrorEnvelope(t, second)
	if body.Type != errTypeRateLimit || body.Code == nil || *body.Code != errCodeRateLimitExceeded {
		t.Fatalf("envelope = %+v", body)
	}
	if second.Header().Get("Retry-After") == "" {
		t.Fatal("rate limited response must carry Retry-After")
	}
}

func TestRetryAfterSecondsRoundsUp(t *testing.T) {
	cases := map[time.Duration]int{
		0:                       1,
		300 * time.Millisecond:  1,
		1 * time.Second:         1,
		1500 * time.Millisecond: 2,
		59 * time.Second:        59,
		rate.InfDuration:        int(rate.InfDuration/time.Second) + 1,
	}
	for delay, want := range cases {
		if got := retryAfterSeconds(delay); got != want {
			t.Errorf("retryAfterSeconds(%s) = %d, want %d", delay, got, want)
		}
	}
}
