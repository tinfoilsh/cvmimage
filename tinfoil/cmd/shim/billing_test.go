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

func TestApplyBillingToResponse_BillsDirectPath(t *testing.T) {
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader([]byte(`{"id":"x","choices":[],"usage":{"prompt_tokens":5,"completion_tokens":3,"total_tokens":8}}`))),
		Request:    httptest.NewRequest(http.MethodPost, "/tokenize", nil),
	}
	resp.Request.Header.Set("Authorization", "Bearer sk-test-key-1234567890")
	collector, events := newRecordingBillingCollector()

	applyBillingToResponse(resp, collector, "test-model", "test-enclave")
	if _, err := io.ReadAll(resp.Body); err != nil {
		t.Fatalf("reading body: %v", err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatalf("closing body: %v", err)
	}

	select {
	case event := <-events:
		if event.PromptTokens != 5 || event.CompletionTokens != 3 {
			t.Fatalf("unexpected direct-path event: %+v", event)
		}
	default:
		t.Fatal("direct-path billing event was not emitted")
	}
}
