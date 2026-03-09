package metrics

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/NVIDIA/go-nvml/pkg/nvml"
	"github.com/klauspost/cpuid/v2"
	"github.com/mackerelio/go-osstat/cpu"
	"github.com/mackerelio/go-osstat/memory"
	"log"

	"tinfoil/internal/auth"
	"tinfoil/internal/config"
)

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

// gpuMetrics collects GPU utilization and memory metrics
func gpuMetrics() (string, int, int, int, error) {
	ret := nvml.Init()
	if ret != nvml.SUCCESS {
		return "", 0, 0, 0, fmt.Errorf("unable to initialize NVML: %v", nvml.ErrorString(ret))
	}
	defer nvml.Shutdown()

	var gpuType string
	var totalMem, usedMem, totalUtil int

	count, ret := nvml.DeviceGetCount()
	if ret != nvml.SUCCESS {
		return "", 0, 0, 0, fmt.Errorf("unable to get device count: %v", nvml.ErrorString(ret))
	}
	for i := range count {
		device, ret := nvml.DeviceGetHandleByIndex(i)
		if ret != nvml.SUCCESS {
			return "", 0, 0, 0, fmt.Errorf("unable to get device at index %d: %v", i, nvml.ErrorString(ret))
		}

		gpuType, ret = nvml.DeviceGetName(device)
		if ret != nvml.SUCCESS {
			return "", 0, 0, 0, fmt.Errorf("unable to get name for device at index %d: %v", i, nvml.ErrorString(ret))
		}

		info, ret := nvml.DeviceGetMemoryInfo_v2(device)
		if ret != nvml.SUCCESS {
			return "", 0, 0, 0, fmt.Errorf("unable to get memory info for device at index %d: %v", i, nvml.ErrorString(ret))
		}
		totalMem += int(info.Total / 1024 / 1024 / 1024) // to GB
		usedMem += int(info.Used / 1024 / 1024 / 1024)

		// Get GPU utilization rates
		rates, ret := nvml.DeviceGetUtilizationRates(device)
		if ret != nvml.SUCCESS {
			return "", 0, 0, 0, fmt.Errorf("unable to get utilization rates for device at index %d: %v", i, nvml.ErrorString(ret))
		} else {
			totalUtil += int(rates.Gpu)
		}
	}

	// Calculate average utilization across all GPUs
	avgUtil := 0
	if count > 0 && totalUtil > 0 {
		avgUtil = totalUtil / count
	}

	return gpuType, totalMem, usedMem, avgUtil, nil
}

// collectMetrics gathers system metrics from CPU, memory, and GPU
func collectMetrics(metadata *config.Metadata) (*Metrics, error) {
	metrics := Metrics{
		ID:      metadata.ID,
		Domain:  metadata.Domain,
		Image:   metadata.Image,
		CPUType: cpuid.CPU.VendorString,
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

	// Set GPU metrics if available
	gpuType, totalMem, usedMem, gpuUtil, err := gpuMetrics()
	if err != nil {
		log.Printf("Warning: failed to get GPU metrics: %v", err)
	}
	metrics.GPUMemTotal = totalMem
	metrics.GPUMemUtil = usedMem
	metrics.GPUUtil = gpuUtil
	metrics.GPUType = gpuType

	return &metrics, nil
}

func HandleMetrics(externalConfig *config.ExternalConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !auth.RequireBearer(externalConfig.MetricsAPIKey, w, r) {
			return
		}

		metricsData, err := collectMetrics(&externalConfig.Metadata)
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
