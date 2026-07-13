package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type trackingReadCloser struct {
	reader io.Reader
	reads  int
}

func (r *trackingReadCloser) Read(p []byte) (int, error) {
	r.reads++
	return r.reader.Read(p)
}

func (r *trackingReadCloser) Close() error { return nil }

func TestStreamTransportDoesNotBufferRequestBody(t *testing.T) {
	body := &trackingReadCloser{reader: strings.NewReader("not-json")}
	transport := &streamTransport{base: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Body != body {
			t.Fatal("request body was replaced before forwarding")
		}
		if body.reads != 0 {
			t.Fatal("request body was read before forwarding")
		}
		return &http.Response{
			StatusCode: http.StatusBadRequest,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("upstream response")),
		}, nil
	})}
	req, err := http.NewRequest(http.MethodPost, "https://upstream.test/v1/chat/completions", body)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := transport.RoundTrip(req); err != nil {
		t.Fatalf("non-JSON request should be forwarded without local buffering: %v", err)
	}
}

func TestStreamTransportDetectsStreamingResponse(t *testing.T) {
	transport := &streamTransport{base: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header: http.Header{
				"Content-Type":   []string{"text/event-stream; charset=utf-8"},
				"Content-Length": []string{"123"},
			},
			ContentLength: 123,
			Body: io.NopCloser(strings.NewReader(
				"data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\ndata: [DONE]\n\n",
			)),
		}, nil
	})}
	req, err := http.NewRequest(http.MethodPost, "https://upstream.test/v1/chat/completions", strings.NewReader(`{"stream":false}`))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), `"p":`) {
		t.Fatalf("stream chunk was not padded: %s", body)
	}
	if resp.Header.Get("Content-Length") != "" || resp.ContentLength != -1 {
		t.Fatal("transformed stream retained stale content-length metadata")
	}
}

func TestStreamTransportForwardsOversizedEvents(t *testing.T) {
	largeContent := strings.Repeat("a", 2*1024*1024)
	event := `data: {"choices":[{"delta":{"content":"` + largeContent + `"}}]}` + "\n\ndata: [DONE]\n\n"
	transport := &streamTransport{base: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
			Body:       io.NopCloser(strings.NewReader(event)),
		}, nil
	})}
	req, err := http.NewRequest(http.MethodPost, "https://upstream.test/v1/chat/completions", strings.NewReader(`{"stream":true}`))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), largeContent) {
		t.Fatal("oversized stream event was truncated")
	}
	if !strings.Contains(string(body), "data: [DONE]") {
		t.Fatal("events after an oversized event were dropped")
	}
}

func TestStreamTransportRejectsUnboundedEvents(t *testing.T) {
	event := "data: " + strings.Repeat("a", maxSSELineBytes+1)
	transport := &streamTransport{base: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
			Body:       io.NopCloser(strings.NewReader(event)),
		}, nil
	})}
	req, err := http.NewRequest(http.MethodPost, "https://upstream.test/v1/chat/completions", strings.NewReader(`{"stream":true}`))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if _, err := io.ReadAll(resp.Body); err == nil {
		t.Fatal("oversized stream event was accepted without a bounded-memory error")
	}
}

type errorAfterReader struct {
	reader io.Reader
	err    error
}

func (r *errorAfterReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	if err == io.EOF {
		return n, r.err
	}
	return n, err
}

func (r *errorAfterReader) Close() error { return nil }

func TestStreamTransportPropagatesUpstreamReadErrors(t *testing.T) {
	upstreamErr := errors.New("upstream connection reset")
	transport := &streamTransport{base: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
			Body: &errorAfterReader{
				reader: strings.NewReader("data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n"),
				err:    upstreamErr,
			},
		}, nil
	})}
	req, err := http.NewRequest(http.MethodPost, "https://upstream.test/v1/chat/completions", strings.NewReader(`{"stream":true}`))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if _, err := io.ReadAll(resp.Body); !errors.Is(err, upstreamErr) {
		t.Fatalf("upstream read error was not preserved: %v", err)
	}
}

func TestStreamTransportIgnoresNonSSEMediaTypes(t *testing.T) {
	body := io.NopCloser(strings.NewReader(`{"choices":[{"delta":{"content":"hi"}}]}`))
	transport := &streamTransport{base: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header: http.Header{
				"Content-Type":   []string{"text/event-streaming"},
				"Content-Length": []string{"42"},
			},
			ContentLength: 42,
			Body:          body,
		}, nil
	})}
	req, err := http.NewRequest(http.MethodPost, "https://upstream.test/v1/chat/completions", strings.NewReader(`{"stream":true}`))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Body != body {
		t.Fatal("non-SSE response body should pass through untouched")
	}
	if resp.Header.Get("Content-Length") != "42" || resp.ContentLength != 42 {
		t.Fatal("non-SSE response content-length metadata was changed")
	}
}

type blockingReadCloser struct {
	started   chan struct{}
	closed    chan struct{}
	startOnce sync.Once
	closeOnce sync.Once
}

func newBlockingReadCloser() *blockingReadCloser {
	return &blockingReadCloser{
		started: make(chan struct{}),
		closed:  make(chan struct{}),
	}
}

func (r *blockingReadCloser) Read([]byte) (int, error) {
	r.startOnce.Do(func() { close(r.started) })
	<-r.closed
	return 0, io.ErrClosedPipe
}

func (r *blockingReadCloser) Close() error {
	r.closeOnce.Do(func() { close(r.closed) })
	return nil
}

func TestStreamTransportClosesUpstreamOnDownstreamDisconnect(t *testing.T) {
	upstream := newBlockingReadCloser()
	transport := &streamTransport{base: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
			Body:       upstream,
		}, nil
	})}
	req, err := http.NewRequest(http.MethodPost, "https://upstream.test/v1/chat/completions", strings.NewReader(`{"stream":true}`))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}

	select {
	case <-upstream.started:
	case <-time.After(time.Second):
		t.Fatal("stream producer did not begin reading upstream")
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-upstream.closed:
	case <-time.After(time.Second):
		t.Fatal("closing the downstream body did not close upstream")
	}
}

func TestAddPaddingToStreamChunk(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		shouldError bool
		validate    func(t *testing.T, output string)
	}{
		{
			name:  "typical streaming chunk with null finish_reason",
			input: `{"id":"chatcmpl-123","object":"chat.completion.chunk","created":1234567890,"model":"deepseek-r1-70b","choices":[{"index":0,"delta":{"role":"assistant","content":"Hello"},"finish_reason":null}]}`,
			validate: func(t *testing.T, output string) {
				var result map[string]interface{}
				if err := json.Unmarshal([]byte(output), &result); err != nil {
					t.Fatalf("Failed to unmarshal output: %v", err)
				}

				// Check that finish_reason is still null
				choices := result["choices"].([]interface{})
				choice := choices[0].(map[string]interface{})
				if choice["finish_reason"] != nil {
					t.Errorf("Expected finish_reason to be null, got %v", choice["finish_reason"])
				}

				// Check that padding was added
				delta := choice["delta"].(map[string]interface{})
				padding, ok := delta["p"].(string)
				if !ok {
					t.Error("Expected padding field 'p' to be added to delta")
				}
				if len(padding) < 4 || len(padding) > 36 {
					t.Errorf("Padding length should be between 4 and 36, got %d", len(padding))
				}

				// Verify padding contains only allowed characters
				allowedChars := "abcdefghijklmnopqrstuvwxyz0123456789"
				for _, char := range padding {
					if !strings.ContainsRune(allowedChars, char) {
						t.Errorf("Invalid character in padding: %c", char)
					}
				}

				// Check that other fields are preserved
				if result["id"] != "chatcmpl-123" {
					t.Error("ID field was not preserved")
				}
				if delta["content"] != "Hello" {
					t.Error("Content field was not preserved")
				}
			},
		},
		{
			name:  "chunk with empty string finish_reason",
			input: `{"id":"chatcmpl-456","choices":[{"index":0,"delta":{"content":"Hi"},"finish_reason":""}]}`,
			validate: func(t *testing.T, output string) {
				var result map[string]interface{}
				if err := json.Unmarshal([]byte(output), &result); err != nil {
					t.Fatalf("Failed to unmarshal output: %v", err)
				}

				choices := result["choices"].([]interface{})
				choice := choices[0].(map[string]interface{})

				// Empty string should be preserved
				if choice["finish_reason"] != "" {
					t.Errorf("Expected finish_reason to be empty string, got %v", choice["finish_reason"])
				}
			},
		},
		{
			name:  "chunk with stop finish_reason",
			input: `{"id":"chatcmpl-789","choices":[{"index":0,"delta":{"content":""},"finish_reason":"stop"}]}`,
			validate: func(t *testing.T, output string) {
				var result map[string]interface{}
				if err := json.Unmarshal([]byte(output), &result); err != nil {
					t.Fatalf("Failed to unmarshal output: %v", err)
				}

				choices := result["choices"].([]interface{})
				choice := choices[0].(map[string]interface{})

				// stop should be preserved
				if choice["finish_reason"] != "stop" {
					t.Errorf("Expected finish_reason to be 'stop', got %v", choice["finish_reason"])
				}
			},
		},
		{
			name:  "chunk without choices",
			input: `{"id":"chatcmpl-end","choices":[]}`,
			validate: func(t *testing.T, output string) {
				// Should return unchanged
				if output != `{"id":"chatcmpl-end","choices":[]}` {
					t.Error("Expected output to be unchanged when no choices")
				}
			},
		},
		{
			name:  "chunk without delta",
			input: `{"id":"chatcmpl-nodelta","choices":[{"index":0,"message":{"content":"test"}}]}`,
			validate: func(t *testing.T, output string) {
				// Should return unchanged when no delta
				var result map[string]interface{}
				if err := json.Unmarshal([]byte(output), &result); err != nil {
					t.Fatalf("Failed to unmarshal output: %v", err)
				}

				choices := result["choices"].([]interface{})
				choice := choices[0].(map[string]interface{})

				if _, hasDelta := choice["delta"]; hasDelta {
					t.Error("Should not have delta field")
				}
			},
		},
		{
			name:        "invalid JSON",
			input:       `{"invalid": json}`,
			shouldError: true,
		},
		{
			name:  "complex nested structure preservation",
			input: `{"id":"complex","choices":[{"index":0,"delta":{"role":"assistant","content":"Test","tool_calls":[{"id":"call_123","type":"function","function":{"name":"test","arguments":"{}"}}]},"finish_reason":null,"logprobs":{"content":[{"token":"Test","logprob":-0.5}]}}],"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}`,
			validate: func(t *testing.T, output string) {
				var result map[string]interface{}
				if err := json.Unmarshal([]byte(output), &result); err != nil {
					t.Fatalf("Failed to unmarshal output: %v", err)
				}

				// Check that complex nested structures are preserved
				choices := result["choices"].([]interface{})
				choice := choices[0].(map[string]interface{})
				delta := choice["delta"].(map[string]interface{})

				// Check tool_calls preservation
				toolCalls, ok := delta["tool_calls"].([]interface{})
				if !ok || len(toolCalls) != 1 {
					t.Error("tool_calls not preserved correctly")
				}

				// Check logprobs preservation
				_, ok = choice["logprobs"].(map[string]interface{})
				if !ok {
					t.Error("logprobs not preserved")
				}

				// Check usage preservation
				usage, ok := result["usage"].(map[string]interface{})
				if !ok || usage["total_tokens"] != float64(15) {
					t.Error("usage not preserved correctly")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output, err := addPaddingToStreamChunk(tt.input)

			if tt.shouldError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if tt.validate != nil {
				tt.validate(t, output)
			}
		})
	}
}
