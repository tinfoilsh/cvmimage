package metrics

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/mackerelio/go-osstat/cpu"
	"github.com/mackerelio/go-osstat/memory"

	"tinfoil/internal/auth"
	"tinfoil/internal/config"
)

func cpuVendor() string {
	data, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return "unknown"
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		if k, v, ok := strings.Cut(line, ":"); ok && strings.TrimSpace(k) == "vendor_id" {
			return strings.TrimSpace(v)
		}
	}
	return "unknown"
}

// Metrics represents the system metrics data structure
type Metrics struct {
	ID          string `json:"id"`
	Domain      string `json:"domain"`
	Image       string `json:"image"`
	CPUUtil     int    `json:"cpu_util"`
	GPUUtil     int    `json:"gpu_util,omitempty"`
	CPUMemUtil  int    `json:"cpu_mem_util"`
	GPUMemUtil  int    `json:"gpu_mem_util,omitempty"`
	CPUMemTotal int    `json:"cpu_mem_total"`
	GPUMemTotal int    `json:"gpu_mem_total,omitempty"`
	CPUType     string `json:"cpu_type"`
	GPUType     string `json:"gpu_type"`
}

// DeviceCollector adds workload-specific device measurements to the host metrics.
type DeviceCollector func(*Metrics) error

// collectMetrics gathers system metrics from CPU, memory, and GPU
func collectMetrics(metadata *config.Metadata, devices DeviceCollector) (*Metrics, error) {
	// The image label is "repo@tag"; empty when the metadata carries no repo.
	var image string
	if metadata.Repo != "" && metadata.Tag != "" {
		image = metadata.Repo + "@" + metadata.Tag
	}
	metrics := Metrics{
		ID:      metadata.ID,
		Domain:  metadata.Domain,
		Image:   image,
		CPUType: cpuVendor(),
	}

	memory, err := memory.Get()
	if err != nil {
		return nil, err
	}
	metrics.CPUMemTotal = int(memory.Total / 1024 / 1024 / 1024) // to GB
	metrics.CPUMemUtil = int(memory.Used / 1024 / 1024 / 1024)

	cpuStats, err := cpu.Get()
	if err != nil {
		return nil, err
	}
	busy := cpuStats.User + cpuStats.System + cpuStats.Nice
	total := busy + cpuStats.Idle
	metrics.CPUUtil = int(float64(busy) / float64(total) * 100)

	if devices != nil {
		if err := devices(&metrics); err != nil {
			log.Printf("Warning: failed to get device metrics: %v", err)
		}
	}

	return &metrics, nil
}

func HandleMetrics(externalConfig *config.ExternalConfig, devices DeviceCollector) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !auth.RequireBearer(externalConfig.MetricsAPIKey, w, r) {
			return
		}

		metricsData, err := collectMetrics(&externalConfig.Metadata, devices)
		if err != nil {
			log.Printf("metrics collection failed: %v", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(metricsData); err != nil {
			log.Printf("metrics encoding failed: %v", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
	}
}
