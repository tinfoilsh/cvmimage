package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"tinfoil/internal/auth"
	"tinfoil/internal/config"
)

var (
	baseLabels = []string{"id", "domain", "image", "cpu_type", "gpu_type"}

	cpuUtilGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "tfshim_cpu_utilization_percent",
			Help: "CPU utilization percentage",
		},
		baseLabels,
	)

	gpuUtilGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "tfshim_gpu_utilization_percent",
			Help: "GPU utilization percentage",
		},
		baseLabels,
	)

	cpuMemUtilGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "tfshim_cpu_memory_used_gb",
			Help: "CPU memory used in GB",
		},
		baseLabels,
	)

	gpuMemUtilGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "tfshim_gpu_memory_used_gb",
			Help: "GPU memory used in GB",
		},
		baseLabels,
	)

	cpuMemTotalGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "tfshim_cpu_memory_total_gb",
			Help: "CPU memory total in GB",
		},
		baseLabels,
	)

	gpuMemTotalGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "tfshim_gpu_memory_total_gb",
			Help: "GPU memory total in GB",
		},
		baseLabels,
	)
)

// updatePrometheusMetrics updates all Prometheus metrics with the latest values
func updatePrometheusMetrics(metrics *Metrics) {
	// Reset all gauge vectors to remove stale label combinations
	cpuUtilGauge.Reset()
	gpuUtilGauge.Reset()
	cpuMemUtilGauge.Reset()
	gpuMemUtilGauge.Reset()
	cpuMemTotalGauge.Reset()
	gpuMemTotalGauge.Reset()

	// Set GPU type to empty string if not available
	gpuType := metrics.GPUType
	if gpuType == "" {
		gpuType = "none"
	}

	baseLabels := prometheus.Labels{
		"id":       metrics.ID,
		"domain":   metrics.Domain,
		"image":    metrics.Image,
		"cpu_type": metrics.CPUType,
		"gpu_type": gpuType,
	}

	// Update CPU metrics
	cpuUtilGauge.With(baseLabels).Set(float64(metrics.CPUUtil))
	cpuMemUtilGauge.With(baseLabels).Set(float64(metrics.CPUMemUtil))
	cpuMemTotalGauge.With(baseLabels).Set(float64(metrics.CPUMemTotal))

	// Update GPU metrics if available
	if metrics.GPUType != "" {
		gpuUtilGauge.With(baseLabels).Set(float64(metrics.GPUUtil))
		gpuMemUtilGauge.With(baseLabels).Set(float64(metrics.GPUMemUtil))
		gpuMemTotalGauge.With(baseLabels).Set(float64(metrics.GPUMemTotal))
	} else {
		// Set GPU metrics to 0 when no GPU is available
		gpuUtilGauge.With(baseLabels).Set(0)
		gpuMemUtilGauge.With(baseLabels).Set(0)
		gpuMemTotalGauge.With(baseLabels).Set(0)
	}
}

// HandlePrometheusMetrics handles the /metrics endpoint for Prometheus scraping
func HandlePrometheusMetrics(metadata *config.Metadata, metricsAPIKey string) http.HandlerFunc {
	registry := prometheus.NewRegistry()
	registry.MustRegister(
		cpuUtilGauge,
		gpuUtilGauge,
		cpuMemUtilGauge,
		gpuMemUtilGauge,
		cpuMemTotalGauge,
		gpuMemTotalGauge,
	)
	handler := promhttp.HandlerFor(registry, promhttp.HandlerOpts{})

	return func(w http.ResponseWriter, r *http.Request) {
		if !auth.RequireBearer(metricsAPIKey, w, r) {
			return
		}

		metrics, err := collectMetrics(metadata)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		updatePrometheusMetrics(metrics)
		handler.ServeHTTP(w, r)
	}
}
