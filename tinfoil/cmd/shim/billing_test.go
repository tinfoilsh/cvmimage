package main

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"testing/iotest"
	"time"

	usagereporting "github.com/tinfoilsh/usage-reporting-go"

	"tinfoil/internal/billing"
)

func TestPrepareBillingRequest_JSONRequest(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/tokenize", strings.NewReader(`{"model":"x"}`))
	req.Header.Set("Content-Type", "application/json")

	streaming, err := prepareBillingRequest(req)
	if err != nil {
		t.Fatalf("prepareBillingRequest() error = %v", err)
	}
	if streaming {
		t.Errorf("streaming = true, want false")
	}
}

func TestPrepareBillingRequest_NonJSON(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader("plain text"))
	req.Header.Set("Content-Type", "text/plain")

	streaming, err := prepareBillingRequest(req)
	if err != nil {
		t.Fatalf("prepareBillingRequest() error = %v", err)
	}
	if streaming {
		t.Errorf("streaming = true, want false for non-JSON")
	}
}

func TestPrepareBillingRequest_GetMethod(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/v1/chat/completions", nil)

	streaming, err := prepareBillingRequest(req)
	if err != nil {
		t.Fatalf("prepareBillingRequest() error = %v", err)
	}
	if streaming {
		t.Errorf("streaming = true, want false for GET")
	}
}

func TestPrepareBillingRequest_ForceStreamingUsageOptions(t *testing.T) {
	body := `{"model":"gpt-4","stream":true,"messages":[]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	streaming, err := prepareBillingRequest(req)
	if err != nil {
		t.Fatalf("prepareBillingRequest() error = %v", err)
	}
	if !streaming {
		t.Fatalf("streaming = false, want true")
	}

	bodyBytes, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("reading restored body: %v", err)
	}
	if !strings.Contains(string(bodyBytes), `"include_usage":true`) {
		t.Errorf("stream_options.include_usage not forced: %s", bodyBytes)
	}
	if !strings.Contains(string(bodyBytes), `"continuous_usage_stats":true`) {
		t.Errorf("stream_options.continuous_usage_stats not forced: %s", bodyBytes)
	}
}

func TestPrepareBillingRequest_PreservesIntegerPrecision(t *testing.T) {
	// Large integer values (e.g. seed) must not lose precision through
	// float64 coercion during unmarshal/re-marshal. json.Number preserves
	// the original representation.
	body := `{"model":"gpt-4","stream":true,"seed":12345678901234567890,"messages":[]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	streaming, err := prepareBillingRequest(req)
	if err != nil {
		t.Fatalf("prepareBillingRequest() error = %v", err)
	}
	if !streaming {
		t.Fatalf("streaming = false, want true")
	}

	bodyBytes, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("reading restored body: %v", err)
	}
	// The large integer must appear exactly as the original, not as a
	// float64 approximation (e.g. 12345678901234568000).
	if !strings.Contains(string(bodyBytes), `"seed":12345678901234567890`) {
		t.Errorf("integer precision lost in re-marshalled body: %s", bodyBytes)
	}
}

func TestPrepareBillingRequest_NonStreamingPreservesOriginalBytes(t *testing.T) {
	// Non-streaming requests must not be re-marshalled; the original bytes
	// (including whitespace and key order) must be preserved.
	body := `{"model":"gpt-4","seed":12345678901234567890,"messages":[{"role":"user","content":"hi"}]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	streaming, err := prepareBillingRequest(req)
	if err != nil {
		t.Fatalf("prepareBillingRequest() error = %v", err)
	}
	if streaming {
		t.Errorf("streaming = true, want false for non-streaming request")
	}

	bodyBytes, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("reading restored body: %v", err)
	}
	if string(bodyBytes) != body {
		t.Errorf("non-streaming body was modified:\ngot:  %s\nwant: %s", bodyBytes, body)
	}
}

func TestPrepareBillingRequest_PreservesClientRequestedUsage(t *testing.T) {
	body := `{"model":"gpt-4","stream":true,"stream_options":{"include_usage":true},"messages":[]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	streaming, err := prepareBillingRequest(req)
	if err != nil {
		t.Fatalf("prepareBillingRequest() error = %v", err)
	}
	if !streaming {
		t.Fatalf("streaming = false, want true")
	}
	if req.Header.Get(clientRequestedUsageHeader) != "true" {
		t.Errorf("clientRequestedUsageHeader not set when client requested usage")
	}
}

func TestPrepareBillingRequest_FullJSONAPICoverage(t *testing.T) {
	paths := []string{
		"/v1/chat/completions",
		"/v1/completions",
		"/v1/responses",
		"/v1/embeddings",
		"/v1/audio/speech",
		"/v1/rerank",
		"/custom/model/api",
	}
	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"model":"client-alias","stream":true}`))
			req.Header.Set("Content-Type", "application/vnd.openai+json; charset=utf-8")
			streaming, err := prepareBillingRequest(req)
			if err != nil {
				t.Fatalf("prepareBillingRequest() error = %v", err)
			}
			if !streaming {
				t.Fatal("streaming = false, want true")
			}
			body, err := io.ReadAll(req.Body)
			if err != nil {
				t.Fatalf("read prepared body: %v", err)
			}
			if !bytes.Contains(body, []byte(`"include_usage":true`)) {
				t.Fatalf("prepared body did not request usage: %s", body)
			}
		})
	}
}

func TestPrepareBillingRequest_RejectsMalformedOrTrailingJSON(t *testing.T) {
	for _, body := range []string{
		`null`,
		`[]`,
		`{"model":"m","stream":true`,
		`{"model":"m","stream":true}{"second":true}`,
		`{"model":"m","stream":true} trailing`,
	} {
		req := httptest.NewRequest(http.MethodPost, "/v1/completions", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if _, err := prepareBillingRequest(req); err == nil {
			t.Fatalf("prepareBillingRequest(%q) succeeded, want error", body)
		}
	}
}

func TestPrepareBillingRequest_RejectsReadError(t *testing.T) {
	readErr := errors.New("synthetic body failure")
	req := httptest.NewRequest(http.MethodPost, "/v1/completions", nil)
	req.Body = io.NopCloser(io.MultiReader(strings.NewReader(`{"model":"m",`), iotest.ErrReader(readErr)))
	req.ContentLength = -1
	req.Header.Set("Content-Type", "application/json")
	if _, err := prepareBillingRequest(req); !errors.Is(err, readErr) {
		t.Fatalf("prepareBillingRequest() error = %v, want wrapped %v", err, readErr)
	}
}

func TestEnsureStreamingUsageOptions_RejectsInvalidValues(t *testing.T) {
	tests := []map[string]any{
		{"stream_options": nil},
		{"stream_options": "invalid"},
		{"stream_options": map[string]any{"include_usage": "true"}},
		{"stream_options": map[string]any{"continuous_usage_stats": 1}},
	}
	for _, body := range tests {
		headers := http.Header{clientRequestedUsageHeader: []string{"true"}}
		if err := ensureStreamingUsageOptions(body, headers); err == nil {
			t.Fatalf("ensureStreamingUsageOptions(%v) succeeded, want error", body)
		}
		if got := headers.Get(clientRequestedUsageHeader); got != "" {
			t.Fatalf("internal usage header survived invalid request: %q", got)
		}
	}
}

func TestEnsureStreamingUsageOptions_ClearsSpoofedHeader(t *testing.T) {
	headers := http.Header{}
	headers.Set(clientRequestedUsageHeader, "true")

	body := map[string]any{
		"stream": true,
		// No stream_options.include_usage — client did not request usage
	}
	if err := ensureStreamingUsageOptions(body, headers); err != nil {
		t.Fatalf("ensureStreamingUsageOptions() error = %v", err)
	}

	if headers.Get(clientRequestedUsageHeader) == "true" {
		t.Errorf("spoofed clientRequestedUsageHeader was not cleared")
	}
}

func TestEnsureStreamingUsageOptions_SetsHeaderWhenRequested(t *testing.T) {
	headers := http.Header{}
	headers.Set(clientRequestedUsageHeader, "true") // spoofed

	body := map[string]any{
		"stream":         true,
		"stream_options": map[string]any{"include_usage": true},
	}
	if err := ensureStreamingUsageOptions(body, headers); err != nil {
		t.Fatalf("ensureStreamingUsageOptions() error = %v", err)
	}

	if headers.Get(clientRequestedUsageHeader) != "true" {
		t.Errorf("clientRequestedUsageHeader should be set when client requested usage")
	}
}

func TestApplyBillingToResponse_NoOpWithoutAPIKey(t *testing.T) {
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader([]byte(`{"id":"x","choices":[],"usage":{"prompt_tokens":5,"completion_tokens":3,"total_tokens":8}}`))),
		Request:    httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil),
	}
	// No Authorization header → no API key

	applyBillingToResponse(resp, nil, "test-model", "test-enclave")

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading body: %v", err)
	}
	resp.Body.Close()
	if !strings.Contains(string(body), "usage") {
		t.Errorf("body should be unchanged (pass-through), got: %s", body)
	}
}

func TestApplyBillingToResponse_ZeroTokenFallbackNonStreaming(t *testing.T) {
	collector, events := newRecordingBillingCollector()

	// Non-streaming 200 response with no usage field — billingCloser should
	// emit a zero-token event on Close.
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader([]byte(`{"id":"x","choices":[]}`))),
		Request:    httptest.NewRequest(http.MethodPost, "/tokenize", nil),
	}
	resp.Request.Header.Set("Authorization", "Bearer sk-test-key-1234567890")

	applyBillingToResponse(resp, collector, "test-model", "test-enclave")

	// Read and close to trigger billingCloser
	io.ReadAll(resp.Body)
	resp.Body.Close()
	select {
	case event := <-events:
		if event.Model != "test-model" || event.TotalTokens != 0 {
			t.Fatalf("unexpected fallback event: %+v", event)
		}
	default:
		t.Fatal("zero-token fallback did not emit an event")
	}
}

func TestApplyBillingToResponse_StreamingDeletesContentLength(t *testing.T) {
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Content-Type":   []string{"text/event-stream"},
			"Content-Length": []string{"123"},
		},
		Body:    io.NopCloser(strings.NewReader("data: {}\n\ndata: [DONE]\n\n")),
		Request: httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil),
	}
	resp.Request.Header.Set("Authorization", "Bearer sk-test-key-1234567890")

	applyBillingToResponse(resp, nil, "test-model", "test-enclave")

	if resp.Header.Get("Content-Length") != "" {
		t.Errorf("Content-Length should be deleted for streaming, got %q", resp.Header.Get("Content-Length"))
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()
}

func TestApplyBillingToResponse_NilCollectorIsNoOp(t *testing.T) {
	body := `{"id":"x","choices":[],"usage":{"prompt_tokens":5,"completion_tokens":3,"total_tokens":8}}`
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader([]byte(body))),
		Request:    httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil),
	}
	resp.Request.Header.Set("Authorization", "Bearer sk-test-key-1234567890")

	applyBillingToResponse(resp, nil, "test-model", "test-enclave")

	out, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading body: %v", err)
	}
	resp.Body.Close()
	if string(out) != body {
		t.Errorf("body changed with nil collector: got %s", out)
	}
}

func TestBillingCloser_EmitsOnce(t *testing.T) {
	calls := 0
	emit := func() { calls++ }
	var called atomic.Bool
	closer := &billingCloser{
		ReadCloser:    io.NopCloser(bytes.NewReader([]byte{})),
		handlerCalled: &called,
		emitEvent:     emit,
	}
	closer.Close()
	closer.Close()
	if calls != 1 {
		t.Errorf("emitEvent called %d times, want 1", calls)
	}
}

func TestBillingCloser_SkipsWhenHandlerCalled(t *testing.T) {
	calls := 0
	emit := func() { calls++ }
	var called atomic.Bool
	called.Store(true)
	closer := &billingCloser{
		ReadCloser:    io.NopCloser(bytes.NewReader([]byte{})),
		handlerCalled: &called,
		emitEvent:     emit,
	}
	closer.Close()
	if calls != 0 {
		t.Errorf("emitEvent called %d times, want 0 when handler was called", calls)
	}
}

// --- alreadyBilledByRouter tests ---

const testUsageContextSecret = "test-usage-context-secret-32-bytes!"

const testAPIKey = "sk-test-key-1234567890"

// TestExtractBearerToken_MatchesHashAPIKeyRoundTrip verifies that the
// shim's extractBearerToken produces the exact string the router would
// hash with usagereporting.HashAPIKey, so the VerifyAPIKeyHash check in
// alreadyBilledByRouter succeeds. The router's manager.BearerToken and
// the shim's extractBearerToken are intentionally identical duplicates in
// separate modules; this test guards against drift in the shim's copy.
func TestExtractBearerToken_MatchesHashAPIKeyRoundTrip(t *testing.T) {
	cases := []struct {
		name   string
		header string
		want   string
	}{
		{"standard", "Bearer " + testAPIKey, testAPIKey},
		{"lowercase scheme", "bearer " + testAPIKey, testAPIKey},
		{"mixed case", "BeArEr " + testAPIKey, testAPIKey},
		{"trailing whitespace", "Bearer " + testAPIKey + "  ", testAPIKey},
		{"no space after scheme", "Bearer" + testAPIKey, ""},
		{"empty", "", ""},
		{"wrong scheme", "Basic " + testAPIKey, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := extractBearerToken(tc.header)
			if got != tc.want {
				t.Fatalf("extractBearerToken(%q) = %q, want %q", tc.header, got, tc.want)
			}
			// When extraction succeeds, the extracted key must verify
			// against a hash of the same key — the exact round-trip the
			// router→shim billing-suppression path depends on.
			if got != "" {
				hash := usagereporting.HashAPIKey(got)
				if !usagereporting.VerifyAPIKeyHash(got, hash) {
					t.Fatalf("VerifyAPIKeyHash mismatch: extracted token does not verify against its own hash")
				}
			}
		})
	}
}

// signUsageContext sets a validly-signed usage-context header on the
// request for the given context fields.
func signUsageContext(t *testing.T, header http.Header, apiKey string, billCustomerRequest bool) {
	t.Helper()
	ctx := usagereporting.Context{
		ParentService:       usagereporting.ServiceRouter,
		APIKeyHash:          usagereporting.HashAPIKey(apiKey),
		BillCustomerRequest: billCustomerRequest,
		Depth:               1,
		IssuedAt:            time.Now().UTC(),
	}
	signExactUsageContext(t, header, ctx)
}

func signExactUsageContext(t *testing.T, header http.Header, ctx usagereporting.Context) {
	t.Helper()
	if err := usagereporting.SetHeaders(header, ctx, testUsageContextSecret); err != nil {
		t.Fatalf("SetHeaders: %v", err)
	}
}

func TestAlreadyBilledByRouter_NoContext_DirectPath(t *testing.T) {
	header := http.Header{}
	// No usage-context header set — direct-path client.
	got := alreadyBilledByRouter(header, testAPIKey, testUsageContextSecret)
	if got {
		t.Errorf("alreadyBilledByRouter = true, want false for direct-path (no context)")
	}
}

func TestAlreadyBilledByRouter_NoSecret(t *testing.T) {
	header := http.Header{}
	signUsageContext(t, header, testAPIKey, false)
	// Shim booted without USAGE_CONTEXT_SECRET — cannot verify, must bill.
	got := alreadyBilledByRouter(header, testAPIKey, "")
	if got {
		t.Errorf("alreadyBilledByRouter = true, want false when secret is empty")
	}
}

func TestAlreadyBilledByRouter_NoAPIKey(t *testing.T) {
	header := http.Header{}
	signUsageContext(t, header, testAPIKey, false)
	// No API key on the request — cannot bind, must bill.
	got := alreadyBilledByRouter(header, "", testUsageContextSecret)
	if got {
		t.Errorf("alreadyBilledByRouter = true, want false when apiKey is empty")
	}
}

func TestAlreadyBilledByRouter_ValidSuppression(t *testing.T) {
	header := http.Header{}
	signUsageContext(t, header, testAPIKey, false)
	got := alreadyBilledByRouter(header, testAPIKey, testUsageContextSecret)
	if !got {
		t.Errorf("alreadyBilledByRouter = false, want true for valid signed context with BillCustomerRequest=false and matching API key")
	}
}

func TestAlreadyBilledByRouter_BillCustomerRequestTrue(t *testing.T) {
	header := http.Header{}
	// Tool-runtime semantics: BillCustomerRequest=true means the downstream
	// should bill its own line item, not suppress.
	signUsageContext(t, header, testAPIKey, true)
	got := alreadyBilledByRouter(header, testAPIKey, testUsageContextSecret)
	if got {
		t.Errorf("alreadyBilledByRouter = true, want false when BillCustomerRequest=true")
	}
}

func TestAlreadyBilledByRouter_BadSignature(t *testing.T) {
	header := http.Header{}
	signUsageContext(t, header, testAPIKey, false)
	// Tamper with the signature.
	header.Set(usagereporting.HeaderUsageContextSignature, "deadbeef")
	got := alreadyBilledByRouter(header, testAPIKey, testUsageContextSecret)
	if got {
		t.Errorf("alreadyBilledByRouter = true, want false for bad signature")
	}
}

func TestAlreadyBilledByRouter_ExpiredContext(t *testing.T) {
	header := http.Header{}
	// Sign with an IssuedAt well outside the skew window.
	ctx := usagereporting.Context{
		ParentService:       usagereporting.ServiceRouter,
		APIKeyHash:          usagereporting.HashAPIKey(testAPIKey),
		BillCustomerRequest: false,
		Depth:               1,
		IssuedAt:            time.Now().UTC().Add(-10 * time.Minute),
	}
	if err := usagereporting.SetHeaders(header, ctx, testUsageContextSecret); err != nil {
		t.Fatalf("SetHeaders: %v", err)
	}
	got := alreadyBilledByRouter(header, testAPIKey, testUsageContextSecret)
	if got {
		t.Errorf("alreadyBilledByRouter = true, want false for expired context")
	}
}

func TestAlreadyBilledByRouter_APIKeyMismatch(t *testing.T) {
	header := http.Header{}
	// Context signed for a different API key.
	signUsageContext(t, header, "sk-other-key-9999999999", false)
	got := alreadyBilledByRouter(header, testAPIKey, testUsageContextSecret)
	if got {
		t.Errorf("alreadyBilledByRouter = true, want false when API key does not match")
	}
}

func TestAlreadyBilledByRouter_RejectsUnexpectedContextSemantics(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*usagereporting.Context)
	}{
		{
			name: "empty API key hash",
			mutate: func(ctx *usagereporting.Context) {
				ctx.APIKeyHash = ""
			},
		},
		{
			name: "unexpected parent service",
			mutate: func(ctx *usagereporting.Context) {
				ctx.ParentService = "tool-runtime"
			},
		},
		{
			name: "unexpected depth",
			mutate: func(ctx *usagereporting.Context) {
				ctx.Depth = 2
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := usagereporting.Context{
				ParentService:       usagereporting.ServiceRouter,
				APIKeyHash:          usagereporting.HashAPIKey(testAPIKey),
				BillCustomerRequest: false,
				Depth:               1,
				IssuedAt:            time.Now().UTC(),
			}
			tc.mutate(&ctx)
			header := http.Header{}
			signExactUsageContext(t, header, ctx)
			if alreadyBilledByRouter(header, testAPIKey, testUsageContextSecret) {
				t.Fatal("alreadyBilledByRouter = true, want false")
			}
		})
	}
}

func TestAlreadyBilledByRouter_HalfHeader(t *testing.T) {
	header := http.Header{}
	// Only the context header, no signature.
	header.Set(usagereporting.HeaderContext, "eyJiaWxsX2N1c3RvbWVyX3JlcXVlc3QiOmZhbHNlfQ")
	got := alreadyBilledByRouter(header, testAPIKey, testUsageContextSecret)
	if got {
		t.Errorf("alreadyBilledByRouter = true, want false when only one half of the header pair is present")
	}
}

func TestPrepareBillingSuppressionValidatesAtIngressAndStripsHeaders(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	signUsageContext(t, req.Header, testAPIKey, false)

	prepareBillingSuppression(req, testAPIKey, testUsageContextSecret)

	if !billingSuppressedFromContext(req.Context()) {
		t.Fatal("valid ingress context did not suppress downstream billing")
	}
	if req.Header.Get(usagereporting.HeaderContext) != "" || req.Header.Get(usagereporting.HeaderUsageContextSignature) != "" {
		t.Fatal("usage-context credentials were forwarded toward the workload")
	}
}

// --- applyBillingToResponse suppression integration tests ---

type recordingBillingCollector struct {
	events chan billing.Event
}

func newRecordingBillingCollector() (*recordingBillingCollector, <-chan billing.Event) {
	events := make(chan billing.Event, 2)
	return &recordingBillingCollector{events: events}, events
}

func (c *recordingBillingCollector) AddEvent(event billing.Event) {
	c.events <- event
}

func TestApplyBillingToResponse_SuppressesWhenAlreadyBilled(t *testing.T) {
	// Non-streaming 200 with a usage field. With a valid suppression context,
	// the billingCloser must NOT be wrapped (alreadyBilled gates it), and the
	// body must still pass through the token extractor unchanged.
	body := `{"id":"x","choices":[],"usage":{"prompt_tokens":5,"completion_tokens":3,"total_tokens":8}}`
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader([]byte(body))),
		Request:    httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil),
	}
	resp.Request.Header.Set("Authorization", "Bearer "+testAPIKey)
	signUsageContext(t, resp.Request.Header, testAPIKey, false)

	collector, events := newRecordingBillingCollector()

	prepareBillingSuppression(resp.Request, testAPIKey, testUsageContextSecret)
	applyBillingToResponse(resp, collector, "test-model", "test-enclave")

	out, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading body: %v", err)
	}
	resp.Body.Close()
	if string(out) != body {
		t.Errorf("body changed when billing suppressed: got %s", out)
	}
	select {
	case event := <-events:
		t.Fatalf("suppressed request emitted billing event: %+v", event)
	default:
	}
}

func TestApplyBillingToResponse_BillsDirectPath(t *testing.T) {
	// Direct-path: no usage-context header. Exactly one event must be delivered.
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader([]byte(`{"id":"x","choices":[],"usage":{"prompt_tokens":5,"completion_tokens":3,"total_tokens":8}}`))),
		Request:    httptest.NewRequest(http.MethodPost, "/tokenize", nil),
	}
	resp.Request.Header.Set("Authorization", "Bearer "+testAPIKey)

	collector, events := newRecordingBillingCollector()

	prepareBillingSuppression(resp.Request, testAPIKey, testUsageContextSecret)
	applyBillingToResponse(resp, collector, "test-model", "test-enclave")

	if _, err := io.ReadAll(resp.Body); err != nil {
		t.Fatalf("reading body: %v", err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatalf("closing body: %v", err)
	}

	var event billing.Event
	select {
	case event = <-events:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for direct-path billing event")
	}
	if event.PromptTokens != 5 || event.CompletionTokens != 3 {
		t.Fatalf("unexpected direct-path event: %+v", event)
	}
	select {
	case extra := <-events:
		t.Fatalf("direct request emitted a second event: %+v", extra)
	default:
	}
}

func TestApplyBillingToResponse_DirectPathNoSecret(t *testing.T) {
	// Shim booted without USAGE_CONTEXT_SECRET. Even if a context header
	// were present (it shouldn't be on the direct path), suppression cannot
	// occur. The billingCloser must be wrapped.
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader([]byte(`{"id":"x","choices":[]}`))),
		Request:    httptest.NewRequest(http.MethodPost, "/tokenize", nil),
	}
	resp.Request.Header.Set("Authorization", "Bearer "+testAPIKey)

	collector, events := newRecordingBillingCollector()

	applyBillingToResponse(resp, collector, "test-model", "test-enclave")

	io.ReadAll(resp.Body)
	resp.Body.Close()
	select {
	case <-events:
	default:
		t.Fatal("direct path without a context secret did not bill")
	}
}
