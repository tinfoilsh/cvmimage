package gpumetrics

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"tinfoil/internal/config"
	"tinfoil/internal/metrics"
)

func TestInferenceMetricsPreserveGPUFields(t *testing.T) {
	snapshot, err := collect(&config.Metadata{ID: "node"}, func() (string, int, int, int, error) { return "test GPU", 80, 40, 17, nil })
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	if err := json.Unmarshal(data, &body); err != nil {
		t.Fatal(err)
	}
	if body["id"] != "node" || body["gpu_type"] != "test GPU" || body["gpu_mem_total"] != float64(80) || body["gpu_util"] != float64(17) || body["cpu_util"] == nil {
		t.Fatalf("inference metrics = %s", data)
	}
	unavailable, err := collect(&config.Metadata{}, func() (string, int, int, int, error) { return "", 0, 0, 0, errors.New("unavailable") })
	if err != nil || unavailable.GPUType != "" {
		t.Fatalf("GPU failure should preserve host metrics: %#v, %v", unavailable, err)
	}
}

func TestInferencePrometheusContractAndFreshLabels(t *testing.T) {
	snapshot := &Metrics{Metrics: metrics.Metrics{ID: "node", Domain: "node.example", Image: "repo@tag", CPUType: "cpu", CPUUtil: 12, CPUMemUtil: 16, CPUMemTotal: 32}, GPUType: "gpu", GPUUtil: 17, GPUMemUtil: 40, GPUMemTotal: 80}
	registry := prometheus.NewRegistry()
	registry.MustRegister(&collector{snapshot: func() (*Metrics, error) { return snapshot, nil }})
	want := map[string]float64{
		"tfshim_cpu_utilization_percent": 12, "tfshim_gpu_utilization_percent": 17,
		"tfshim_cpu_memory_used_gb": 16, "tfshim_gpu_memory_used_gb": 40,
		"tfshim_cpu_memory_total_gb": 32, "tfshim_gpu_memory_total_gb": 80,
	}
	for _, gpu := range []string{"gpu", ""} {
		snapshot.GPUType = gpu
		families, err := registry.Gather()
		if err != nil {
			t.Fatal(err)
		}
		if len(families) != len(want) {
			t.Fatalf("families = %d", len(families))
		}
		for _, family := range families {
			samples := family.GetMetric()
			if len(samples) != 1 {
				t.Fatalf("stale samples for %s", family.GetName())
			}
			sample := samples[0]
			expected, ok := want[family.GetName()]
			if !ok {
				t.Fatalf("unexpected metric %s", family.GetName())
			}
			if gpu == "" && strings.HasPrefix(family.GetName(), "tfshim_gpu_") {
				expected = 0
			}
			if sample.GetGauge().GetValue() != expected {
				t.Fatalf("%s = %v, want %v", family.GetName(), sample.GetGauge().GetValue(), expected)
			}
			labels := map[string]string{}
			for _, label := range sample.GetLabel() {
				labels[label.GetName()] = label.GetValue()
			}
			expectedGPU := gpu
			if expectedGPU == "" {
				expectedGPU = "none"
			}
			if len(labels) != 5 || labels["gpu_type"] != expectedGPU || labels["cpu_type"] != "cpu" || labels["id"] != "node" || labels["domain"] != "node.example" || labels["image"] != "repo@tag" {
				t.Fatalf("labels = %v", labels)
			}
		}
	}
}

func TestPrometheusAuthenticatesBeforeDeviceCollection(t *testing.T) {
	calls := 0
	handler := metrics.PrometheusHandler("test-key", &collector{snapshot: func() (*Metrics, error) { calls++; return &Metrics{}, nil }})
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
	if recorder.Code != http.StatusUnauthorized || calls != 0 {
		t.Fatalf("status=%d calls=%d", recorder.Code, calls)
	}
}
