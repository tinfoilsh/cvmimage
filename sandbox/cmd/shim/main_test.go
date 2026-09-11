package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	shimconfig "tinfoil/internal/config"
)

func TestSandboxObservabilityRejectsGPUs(t *testing.T) {
	for _, count := range []int{-1, 1, 8} {
		if _, err := shimSpec().Observability(&shimconfig.Config{ExpectedGPUs: count}, &shimconfig.ExternalConfig{}); err == nil {
			t.Fatalf("accepted GPU count %d", count)
		}
	}
}

func TestSandboxObservability(t *testing.T) {
	external := &shimconfig.ExternalConfig{MetricsAPIKey: "test-key"}
	observability, err := shimSpec().Observability(&shimconfig.Config{}, external)
	if err != nil {
		t.Fatal(err)
	}
	if evidence, err := observability.DeviceEvidence([32]byte{}); err != nil || len(evidence) != 0 {
		t.Fatalf("CPU-only evidence: %v, %v", evidence, err)
	}
	if observability.Handlers["/.well-known/tinfoil-containers"] != nil {
		t.Fatal("sandbox registered container diagnostics")
	}
	for _, path := range []string{"/.well-known/tinfoil-metrics", "/.well-known/metrics"} {
		handler := observability.Handlers[path]
		if handler == nil {
			t.Fatalf("missing route %s", path)
		}
		for _, key := range []string{"", "wrong", "test-key"} {
			request := httptest.NewRequest(http.MethodGet, path, nil)
			request.Header.Set("Authorization", "Bearer "+key)
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			if key != "test-key" {
				if recorder.Code != http.StatusUnauthorized {
					t.Fatalf("%s: unauthorized status=%d", path, recorder.Code)
				}
				continue
			}
			if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), "cpu_") || strings.Contains(recorder.Body.String(), "gpu_") {
				t.Fatalf("%s: %d %s", path, recorder.Code, recorder.Body)
			}
		}
	}
}
