package metrics

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func TestContainerPrometheusCollector(t *testing.T) {
	collector := newContainerPrometheusCollector()
	collector.update(&Metrics{
		ID:      "enclave-1",
		Domain:  "model.example.com",
		Image:   "example/model@v1",
		CPUType: "AuthenticAMD",
	}, []containerMetricStatus{{
		Name:          "model",
		Status:        "restarting",
		RestartCount:  4,
		RestartCounts: map[string]int{"oom_killed": 1, "nonzero_exit": 1},
		OOMKilled:     true,
		ExitCode:      137,
		Health: &containerMetricHealth{
			Status:        "unhealthy",
			FailingStreak: 3,
		},
	}})

	registry := prometheus.NewPedanticRegistry()
	registry.MustRegister(collector)
	recorder := httptest.NewRecorder()
	promhttp.HandlerFor(registry, promhttp.HandlerOpts{}).ServeHTTP(recorder, httptest.NewRequest("GET", "/metrics", nil))
	if recorder.Code != 200 {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	body := recorder.Body.String()
	for _, expected := range []string{
		`# TYPE tfshim_container_restarts_total counter`,
		`tfshim_container_restarting{container="model",cpu_type="AuthenticAMD",domain="model.example.com",gpu_type="none",id="enclave-1",image="example/model@v1"} 1`,
		`tfshim_container_restarts_total{container="model",cpu_type="AuthenticAMD",domain="model.example.com",gpu_type="none",id="enclave-1",image="example/model@v1",reason="nonzero_exit"} 1`,
		`tfshim_container_restarts_total{container="model",cpu_type="AuthenticAMD",domain="model.example.com",gpu_type="none",id="enclave-1",image="example/model@v1",reason="oom_killed"} 1`,
		`tfshim_container_restarts_total{container="model",cpu_type="AuthenticAMD",domain="model.example.com",gpu_type="none",id="enclave-1",image="example/model@v1",reason="unknown"} 2`,
		`tfshim_container_oom_killed{container="model",cpu_type="AuthenticAMD",domain="model.example.com",gpu_type="none",id="enclave-1",image="example/model@v1"} 1`,
		`tfshim_container_last_exit_code{container="model",cpu_type="AuthenticAMD",domain="model.example.com",gpu_type="none",id="enclave-1",image="example/model@v1"} 137`,
		`tfshim_container_state{container="model",cpu_type="AuthenticAMD",domain="model.example.com",gpu_type="none",id="enclave-1",image="example/model@v1",state="restarting"} 1`,
		`tfshim_container_health_status{container="model",cpu_type="AuthenticAMD",domain="model.example.com",gpu_type="none",id="enclave-1",image="example/model@v1",status="unhealthy"} 1`,
		`tfshim_container_health_failing_streak{container="model",cpu_type="AuthenticAMD",domain="model.example.com",gpu_type="none",id="enclave-1",image="example/model@v1"} 3`,
	} {
		if !strings.Contains(body, expected) {
			t.Errorf("metrics output missing %q:\n%s", expected, body)
		}
	}
}

func TestNormalizedRestartCountsBackfillsUnknown(t *testing.T) {
	counts := normalizedRestartCounts(containerMetricStatus{
		RestartCount:  5,
		RestartCounts: map[string]int{"oom_killed": 2},
	})
	if counts["oom_killed"] != 2 || counts["unknown"] != 3 {
		t.Fatalf("counts = %#v", counts)
	}
}
