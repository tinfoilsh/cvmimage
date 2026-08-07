package billing

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	usagereporting "github.com/tinfoilsh/usage-reporting-go"
)

func setupCollectorTest(t *testing.T) (*Collector, func() usagereporting.Batch) {
	t.Helper()

	bodies := make(chan []byte, 1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read body: %v", err)
		}
		bodies <- buf
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	c, err := newCollector(server.URL, "shim-test", "test-secret", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Stop)

	readBatch := func() usagereporting.Batch {
		t.Helper()
		c.reporter.Flush(context.Background())

		var body []byte
		select {
		case body = <-bodies:
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for billing event delivery")
		}

		var batch usagereporting.Batch
		if err := json.Unmarshal(body, &batch); err != nil {
			t.Fatalf("decode batch: %v", err)
		}
		if len(batch.Events) != 1 {
			t.Fatalf("expected 1 event, got %d", len(batch.Events))
		}
		return batch
	}

	return c, readBatch
}

// TestCollectorEmitsCustomerRequestAndTokenMeters verifies that a billing
// event flushed through the reporter carries CustomerRequests=1 and exactly
// the canonical input/output token meters (no requests meter).
func TestCollectorEmitsCustomerRequestAndTokenMeters(t *testing.T) {
	c, readBatch := setupCollectorTest(t)

	c.AddEvent(Event{
		Timestamp:        time.Date(2026, 5, 7, 12, 0, 0, 0, time.UTC),
		Model:            "glm-5-2",
		PromptTokens:     11,
		CompletionTokens: 7,
		TotalTokens:      18,
		RequestID:        "req-1",
		Enclave:          "glm-5-2.inference.tinfoil.sh",
		RequestPath:      "/v1/chat/completions",
		Streaming:        true,
		APIKey:           "sk-test-1234567890",
	})

	batch := readBatch()
	got := batch.Events[0]

	if got.Operation.Service != usagereporting.ServiceRouter {
		t.Errorf("service mismatch: got %q want %q", got.Operation.Service, usagereporting.ServiceRouter)
	}
	if got.Operation.Name != usagereporting.OperationRouterModelRequest {
		t.Errorf("operation mismatch: got %q want %q", got.Operation.Name, usagereporting.OperationRouterModelRequest)
	}
	if got.CustomerRequests != 1 {
		t.Errorf("customer requests mismatch: got %d want 1", got.CustomerRequests)
	}

	meters := make(map[string]int64)
	for _, m := range got.Meters {
		meters[m.Name] = m.Quantity
	}
	if meters[usagereporting.MeterInputTokens] != 11 {
		t.Errorf("input_tokens mismatch: got %d want 11", meters[usagereporting.MeterInputTokens])
	}
	if meters[usagereporting.MeterOutputTokens] != 7 {
		t.Errorf("output_tokens mismatch: got %d want 7", meters[usagereporting.MeterOutputTokens])
	}
	if _, hasRequestsMeter := meters["requests"]; hasRequestsMeter {
		t.Errorf("billing event should not emit a requests meter; got %+v", meters)
	}

	if got.Attributes["model"] != "glm-5-2" {
		t.Errorf("model attribute mismatch: got %q", got.Attributes["model"])
	}
	if got.Attributes["streaming"] != "true" {
		t.Errorf("streaming attribute mismatch: got %q", got.Attributes["streaming"])
	}
	if got.Attributes["enclave"] != "glm-5-2.inference.tinfoil.sh" {
		t.Errorf("enclave attribute mismatch: got %q", got.Attributes["enclave"])
	}
	if got.Attributes["route"] != "/v1/chat/completions" {
		t.Errorf("route attribute mismatch: got %q", got.Attributes["route"])
	}
}

func TestCollectorEmitsCachedInputTokensMeterWhenPresent(t *testing.T) {
	c, readBatch := setupCollectorTest(t)

	c.AddEvent(Event{
		Timestamp:          time.Date(2026, 5, 7, 12, 0, 0, 0, time.UTC),
		Model:              "glm-5-2",
		PromptTokens:       100,
		CachedPromptTokens: 64,
		CompletionTokens:   7,
		TotalTokens:        107,
		RequestID:          "req-1",
		APIKey:             "tk_test",
	})

	batch := readBatch()

	meters := make(map[string]int64)
	for _, m := range batch.Events[0].Meters {
		meters[m.Name] = m.Quantity
	}
	if meters[usagereporting.MeterInputTokens] != 100 {
		t.Errorf("input_tokens mismatch: got %d want 100", meters[usagereporting.MeterInputTokens])
	}
	if meters[usagereporting.MeterCachedInputTokens] != 64 {
		t.Errorf("cached_input_tokens mismatch: got %d want 64", meters[usagereporting.MeterCachedInputTokens])
	}
	if meters[usagereporting.MeterOutputTokens] != 7 {
		t.Errorf("output_tokens mismatch: got %d want 7", meters[usagereporting.MeterOutputTokens])
	}
}

func TestCollectorOmitsCachedMeterWhenZero(t *testing.T) {
	c, readBatch := setupCollectorTest(t)

	c.AddEvent(Event{
		Timestamp:    time.Date(2026, 5, 7, 12, 0, 0, 0, time.UTC),
		Model:        "glm-5-2",
		PromptTokens: 100,
		APIKey:       "tk_test",
	})

	batch := readBatch()
	for _, m := range batch.Events[0].Meters {
		if m.Name == usagereporting.MeterCachedInputTokens {
			t.Fatalf("cached_input_tokens meter should be omitted when zero, got %+v", batch.Events[0].Meters)
		}
	}
}

func TestCollectorFallsBackToTotalTokensWhenSplitMissing(t *testing.T) {
	c, readBatch := setupCollectorTest(t)

	c.AddEvent(Event{
		Timestamp:   time.Date(2026, 5, 7, 12, 0, 0, 0, time.UTC),
		Model:       "glm-5-2",
		TotalTokens: 18,
		RequestID:   "req-1",
		APIKey:      "tk_test",
	})

	batch := readBatch()

	meters := make(map[string]int64)
	for _, m := range batch.Events[0].Meters {
		meters[m.Name] = m.Quantity
	}
	if meters[usagereporting.MeterInputTokens] != 18 {
		t.Errorf("input_tokens mismatch: got %d want 18", meters[usagereporting.MeterInputTokens])
	}
	if meters[usagereporting.MeterOutputTokens] != 0 {
		t.Errorf("output_tokens mismatch: got %d want 0", meters[usagereporting.MeterOutputTokens])
	}
}

func TestNewCollectorRejectsInvalidConfiguration(t *testing.T) {
	for _, test := range []struct {
		name     string
		endpoint string
		id       string
		secret   string
	}{
		{name: "missing endpoint", id: "model", secret: "secret"},
		{name: "plaintext endpoint", endpoint: "http://api.example", id: "model", secret: "secret"},
		{name: "missing endpoint host", endpoint: "https://", id: "model", secret: "secret"},
		{name: "endpoint credentials", endpoint: "https://user@api.example", id: "model", secret: "secret"},
		{name: "endpoint query", endpoint: "https://api.example?target=other", id: "model", secret: "secret"},
		{name: "missing reporter ID", endpoint: "https://api.example", secret: "secret"},
		{name: "padded reporter ID", endpoint: "https://api.example", id: " model", secret: "secret"},
		{name: "missing reporter secret", endpoint: "https://api.example", id: "model"},
	} {
		t.Run(test.name, func(t *testing.T) {
			collector, err := NewCollector(test.endpoint, test.id, test.secret)
			if err == nil || collector != nil {
				t.Fatalf("NewCollector() = (%v, %v), want nil collector and error", collector, err)
			}
		})
	}
}
