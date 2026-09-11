package gpumetrics

import (
	"fmt"
	"tinfoil/inference/internal/nvml"
	"tinfoil/internal/metrics"
)

func Collect(m *metrics.Metrics) error {
	var err error
	m.GPUType, m.GPUMemTotal, m.GPUMemUtil, m.GPUUtil, err = gpuMetrics()
	return err
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
