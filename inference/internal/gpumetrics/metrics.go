package gpumetrics

import (
	"log"
	"net/http"

	"tinfoil/internal/config"
	"tinfoil/internal/metrics"
)

// Metrics preserves the inference metrics response, including GPU fields.
type Metrics struct {
	metrics.Metrics
	GPUUtil     int    `json:"gpu_util,omitempty"`
	GPUMemUtil  int    `json:"gpu_mem_util,omitempty"`
	GPUMemTotal int    `json:"gpu_mem_total,omitempty"`
	GPUType     string `json:"gpu_type"`
}

func collect(metadata *config.Metadata, devices func() (string, int, int, int, error)) (*Metrics, error) {
	host, err := metrics.Collect(metadata)
	if err != nil {
		return nil, err
	}
	snapshot := &Metrics{Metrics: *host}
	snapshot.GPUType, snapshot.GPUMemTotal, snapshot.GPUMemUtil, snapshot.GPUUtil, err = devices()
	if err != nil {
		log.Printf("Warning: failed to get device metrics: %v", err)
	}
	return snapshot, nil
}

func HandleMetrics(external *config.ExternalConfig) http.HandlerFunc {
	return metrics.JSONHandler(external.MetricsAPIKey, func() (any, error) {
		return collect(&external.Metadata, gpuMetrics)
	})
}

func HandlePrometheusMetrics(metadata *config.Metadata, apiKey string) http.HandlerFunc {
	return metrics.PrometheusHandler(apiKey, &collector{snapshot: func() (*Metrics, error) {
		return collect(metadata, gpuMetrics)
	}})
}
