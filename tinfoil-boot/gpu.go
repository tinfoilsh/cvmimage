package main

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	nvidiaVendorID    = "0x10de"
	multiGPUThreshold = 12 // 8 GPUs + 4 NVSwitches
)

type GPUInfo struct {
	HasNvidia   bool
	DeviceCount int
	IsMultiGPU  bool
}

// detectGPUs scans PCI devices for NVIDIA GPUs
func detectGPUs() (*GPUInfo, error) {
	info := &GPUInfo{}

	// Scan /sys/bus/pci/devices for NVIDIA devices
	pciPath := "/sys/bus/pci/devices"
	entries, err := os.ReadDir(pciPath)
	if err != nil {
		return nil, fmt.Errorf("reading PCI devices: %w", err)
	}

	for _, entry := range entries {
		vendorPath := filepath.Join(pciPath, entry.Name(), "vendor")
		vendorData, err := os.ReadFile(vendorPath)
		if err != nil {
			continue
		}

		vendor := strings.TrimSpace(string(vendorData))
		if vendor == nvidiaVendorID {
			info.DeviceCount++
		}
	}

	info.HasNvidia = info.DeviceCount > 0
	info.IsMultiGPU = info.DeviceCount >= multiGPUThreshold

	if info.HasNvidia {
		slog.Info("NVIDIA devices detected",
			"count", info.DeviceCount,
			"multi_gpu", info.IsMultiGPU)
	}

	return info, nil
}

func verifyGPUAttestation(info *GPUInfo) error {
	var cmd *exec.Cmd
	if info.IsMultiGPU {
		slog.Info("running PPCIe attestation verification")
		cmd = exec.Command(
			"/bin/bash", "-c",
			"source /opt/venv-attestation/bin/activate && python3 -m ppcie.verifier.verification --gpu-attestation-mode=LOCAL --switch-attestation-mode=LOCAL",
		)
	} else {
		slog.Info("running GPU attestation verification")
		cmd = exec.Command(
			"/bin/bash", "-c",
			"source /opt/venv-attestation/bin/activate && python3 -m verifier.cc_admin",
		)
	}

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Dir = ramdiskPath

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("attestation verification failed: %w", err)
	}

	slog.Info("GPU attestation verified")
	return nil
}
