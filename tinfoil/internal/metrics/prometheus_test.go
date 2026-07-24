package metrics

import (
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"tinfoil/internal/config"
)

func TestRenderPrometheusMetricsMatchesLegacyFormat(t *testing.T) {
	values := prometheusValuesFromMetrics(&Metrics{
		ID:          "id\\\"\n",
		Domain:      "domain",
		Image:       "image",
		CPUUtil:     1,
		GPUUtil:     2,
		CPUMemUtil:  3,
		GPUMemUtil:  4,
		CPUMemTotal: 5,
		GPUMemTotal: 6,
		CPUType:     "cpu",
		GPUType:     "gpu",
	})
	output, err := renderPrometheusMetrics(values)
	if err != nil {
		t.Fatal(err)
	}
	want := `# HELP tfshim_cpu_memory_total_gb CPU memory total in GB
# TYPE tfshim_cpu_memory_total_gb gauge
tfshim_cpu_memory_total_gb{cpu_type="cpu",domain="domain",gpu_type="gpu",id="id\\\"\n",image="image"} 5
# HELP tfshim_cpu_memory_used_gb CPU memory used in GB
# TYPE tfshim_cpu_memory_used_gb gauge
tfshim_cpu_memory_used_gb{cpu_type="cpu",domain="domain",gpu_type="gpu",id="id\\\"\n",image="image"} 3
# HELP tfshim_cpu_utilization_percent CPU utilization percentage
# TYPE tfshim_cpu_utilization_percent gauge
tfshim_cpu_utilization_percent{cpu_type="cpu",domain="domain",gpu_type="gpu",id="id\\\"\n",image="image"} 1
# HELP tfshim_gpu_memory_total_gb GPU memory total in GB
# TYPE tfshim_gpu_memory_total_gb gauge
tfshim_gpu_memory_total_gb{cpu_type="cpu",domain="domain",gpu_type="gpu",id="id\\\"\n",image="image"} 6
# HELP tfshim_gpu_memory_used_gb GPU memory used in GB
# TYPE tfshim_gpu_memory_used_gb gauge
tfshim_gpu_memory_used_gb{cpu_type="cpu",domain="domain",gpu_type="gpu",id="id\\\"\n",image="image"} 4
# HELP tfshim_gpu_utilization_percent GPU utilization percentage
# TYPE tfshim_gpu_utilization_percent gauge
tfshim_gpu_utilization_percent{cpu_type="cpu",domain="domain",gpu_type="gpu",id="id\\\"\n",image="image"} 2
`
	if string(output) != want {
		t.Fatalf("output mismatch\n--- got ---\n%s--- want ---\n%s", output, want)
	}

	second, err := renderPrometheusMetrics(values)
	if err != nil {
		t.Fatal(err)
	}
	if string(second) != string(output) {
		t.Fatal("rendering is not deterministic")
	}
}

func TestPrometheusValuesWithoutGPU(t *testing.T) {
	values := prometheusValuesFromMetrics(&Metrics{GPUUtil: 7, GPUMemUtil: 8, GPUMemTotal: 9})
	if values.gpuType != "none" {
		t.Fatalf("gpuType = %q, want none", values.gpuType)
	}
	output, err := renderPrometheusMetrics(values)
	if err != nil {
		t.Fatal(err)
	}
	for _, sample := range []string{
		`tfshim_gpu_memory_total_gb{cpu_type="",domain="",gpu_type="none",id="",image=""} 0`,
		`tfshim_gpu_memory_used_gb{cpu_type="",domain="",gpu_type="none",id="",image=""} 0`,
		`tfshim_gpu_utilization_percent{cpu_type="",domain="",gpu_type="none",id="",image=""} 0`,
	} {
		if !strings.Contains(string(output), sample) {
			t.Fatalf("output missing %q:\n%s", sample, output)
		}
	}
}

func TestRenderPrometheusMetricsRejectsNonFiniteValues(t *testing.T) {
	for _, value := range []float64{math.NaN(), math.Inf(1), math.Inf(-1)} {
		values := prometheusValues{cpuUtil: value}
		if _, err := renderPrometheusMetrics(values); err == nil {
			t.Fatalf("renderPrometheusMetrics(%v) succeeded", value)
		}
	}
}

func TestRenderPrometheusMetricsBoundsOutput(t *testing.T) {
	values := prometheusValues{id: strings.Repeat(`\\`, maxPrometheusOutputBytes)}
	if _, err := renderPrometheusMetrics(values); !errors.Is(err, errPrometheusOutputTooLarge) {
		t.Fatalf("error = %v, want %v", err, errPrometheusOutputTooLarge)
	}
}

func TestHandlePrometheusMetricsPreservesAuthAndErrors(t *testing.T) {
	t.Run("auth before collection", func(t *testing.T) {
		var calls atomic.Int32
		handler := handlePrometheusMetrics(&config.Metadata{}, "secret", func(*config.Metadata) (*Metrics, error) {
			calls.Add(1)
			return &Metrics{}, nil
		})
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/.well-known/metrics", nil))
		if recorder.Code != http.StatusUnauthorized || recorder.Body.String() != "Unauthorized\n" {
			t.Fatalf("response = %d %q", recorder.Code, recorder.Body.String())
		}
		if calls.Load() != 0 {
			t.Fatalf("collector called %d times", calls.Load())
		}
	})

	t.Run("collection error", func(t *testing.T) {
		handler := handlePrometheusMetrics(&config.Metadata{}, "", func(*config.Metadata) (*Metrics, error) {
			return nil, errors.New("collection failed")
		})
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/.well-known/metrics", nil))
		if recorder.Code != http.StatusInternalServerError || recorder.Body.String() != "collection failed\n" {
			t.Fatalf("response = %d %q", recorder.Code, recorder.Body.String())
		}
	})

	t.Run("success content type", func(t *testing.T) {
		handler := handlePrometheusMetrics(&config.Metadata{}, "", func(*config.Metadata) (*Metrics, error) {
			return &Metrics{}, nil
		})
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/.well-known/metrics", nil))
		if recorder.Code != http.StatusOK {
			t.Fatalf("status = %d", recorder.Code)
		}
		if got := recorder.Header().Get("Content-Type"); got != prometheusContentType {
			t.Fatalf("Content-Type = %q, want %q", got, prometheusContentType)
		}
	})

	t.Run("encoding failure is closed", func(t *testing.T) {
		handler := handlePrometheusMetrics(&config.Metadata{}, "", func(*config.Metadata) (*Metrics, error) {
			return &Metrics{ID: strings.Repeat(`\\`, maxPrometheusOutputBytes)}, nil
		})
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/.well-known/metrics", nil))
		if recorder.Code != http.StatusInternalServerError || recorder.Body.String() != "internal server error\n" {
			t.Fatalf("response = %d %q", recorder.Code, recorder.Body.String())
		}
	})
}

func TestHandlePrometheusMetricsConcurrent(t *testing.T) {
	const requests = 256
	var sequence atomic.Int64
	handler := handlePrometheusMetrics(&config.Metadata{}, "", func(*config.Metadata) (*Metrics, error) {
		value := int(sequence.Add(1))
		return &Metrics{
			ID:          fmt.Sprintf("request-%d", value),
			CPUUtil:     value,
			GPUUtil:     value,
			CPUMemUtil:  value,
			GPUMemUtil:  value,
			CPUMemTotal: value,
			GPUMemTotal: value,
			GPUType:     "gpu",
		}, nil
	})

	start := make(chan struct{})
	errorChannel := make(chan error, requests)
	var waitGroup sync.WaitGroup
	for range requests {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			<-start
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/.well-known/metrics", nil))
			if recorder.Code != http.StatusOK {
				errorChannel <- fmt.Errorf("status = %d", recorder.Code)
				return
			}
			var requestID string
			samples := 0
			for line := range strings.SplitSeq(strings.TrimSpace(recorder.Body.String()), "\n") {
				if strings.HasPrefix(line, "#") {
					continue
				}
				samples++
				idStart := strings.Index(line, `id="request-`)
				if idStart < 0 {
					errorChannel <- fmt.Errorf("missing request id in %q", line)
					return
				}
				idStart += len(`id="request-`)
				idEnd := strings.IndexByte(line[idStart:], '"')
				if idEnd < 0 {
					errorChannel <- fmt.Errorf("unterminated request id in %q", line)
					return
				}
				lineRequestID := line[idStart : idStart+idEnd]
				if requestID == "" {
					requestID = lineRequestID
				} else if lineRequestID != requestID {
					errorChannel <- fmt.Errorf("mixed request ids %s and %s", requestID, lineRequestID)
					return
				}
				if !strings.HasSuffix(line, " "+requestID) {
					errorChannel <- fmt.Errorf("sample value does not match request %s: %q", requestID, line)
					return
				}
			}
			if samples != 6 {
				errorChannel <- fmt.Errorf("samples = %d, want 6", samples)
			}
		}()
	}
	close(start)
	waitGroup.Wait()
	close(errorChannel)
	for err := range errorChannel {
		t.Error(err)
	}
	if got := sequence.Load(); got != requests {
		t.Fatalf("collector calls = %d, want %d", got, requests)
	}
}
