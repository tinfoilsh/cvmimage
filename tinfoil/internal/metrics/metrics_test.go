package metrics

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"tinfoil/internal/config"
)

func TestHostMetricsContainOnlyCPUAndMemory(t *testing.T) {
	external := &config.ExternalConfig{MetricsAPIKey: "test-key", Metadata: config.Metadata{ID: "node", Repo: "repo", Tag: "tag"}}
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("Authorization", "Bearer test-key")
	recorder := httptest.NewRecorder()
	HandleMetrics(external).ServeHTTP(recorder, request)
	var body map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if recorder.Code != http.StatusOK || body["id"] != "node" || body["image"] != "repo@tag" || body["cpu_mem_total"] == nil {
		t.Fatalf("metrics: %d %s", recorder.Code, recorder.Body)
	}
	for name := range body {
		if strings.HasPrefix(name, "gpu_") {
			t.Fatalf("host metrics contain %s", name)
		}
	}
	recorder = httptest.NewRecorder()
	HandlePrometheusMetrics(&external.Metadata, external.MetricsAPIKey).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), "tfshim_cpu_utilization_percent") || strings.Contains(recorder.Body.String(), "gpu_") {
		t.Fatalf("host scrape: %d %s", recorder.Code, recorder.Body)
	}
}

func TestJSONMetricsAuthenticateBeforeCollection(t *testing.T) {
	calls := 0
	handler := JSONHandler("test-key", func() (any, error) { calls++; return map[string]int{"value": 1}, nil })
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
	if recorder.Code != http.StatusUnauthorized || calls != 0 {
		t.Fatalf("status=%d calls=%d", recorder.Code, calls)
	}
}
