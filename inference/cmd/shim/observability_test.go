package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	shimconfig "tinfoil/internal/config"
)

func TestInferenceObservability(t *testing.T) {
	config := &shimconfig.Config{}
	external := &shimconfig.ExternalConfig{MetricsAPIKey: "test-key"}
	observability, err := shimSpec().Observability(config, external)
	if err != nil {
		t.Fatal(err)
	}
	config.ExpectedGPUs = -1
	if evidence, err := observability.DeviceEvidence([32]byte{}); err != nil || len(evidence) != 0 {
		t.Fatalf("provider did not retain configured GPU count: %v, %v", evidence, err)
	}
	if observability.EvidenceUnavailable != "GPU attestation evidence unavailable" {
		t.Fatalf("changed attestation failure response: %q", observability.EvidenceUnavailable)
	}
	if observability.Handlers["/.well-known/tinfoil-containers"] == nil {
		t.Fatal("container diagnostics missing")
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
			if recorder.Code != http.StatusOK {
				t.Fatalf("%s: %d %s", path, recorder.Code, recorder.Body)
			}
			if path == "/.well-known/tinfoil-metrics" {
				var body map[string]any
				if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
					t.Fatal(err)
				}
				if _, ok := body["gpu_type"]; !ok {
					t.Fatal("GPU field missing from inference metrics")
				}
			} else if !strings.Contains(recorder.Body.String(), "tfshim_gpu_utilization_percent") {
				t.Fatal("GPU series missing from inference scrape")
			}
		}
	}
}
