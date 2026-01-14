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

// GPUInfo contains detected GPU information
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

// initializeNvidiaGPUs loads the NVIDIA driver and starts related services
func initializeNvidiaGPUs(info *GPUInfo) error {
	// Load required crypto modules
	cryptoModules := []string{"ecdsa_generic", "ecdh"}
	for _, mod := range cryptoModules {
		if err := loadModule(mod, ""); err != nil {
			return fmt.Errorf("loading %s: %w", mod, err)
		}
	}

	// Load NVIDIA driver with appropriate options
	var nvidiaOpts string
	if info.IsMultiGPU {
		nvidiaOpts = "NVreg_RegistryDwords=RmEnableProtectedPcie=0x1"
		slog.Info("loading NVIDIA driver with PPCIe enabled")
	} else {
		slog.Info("loading NVIDIA driver in standard mode")
	}

	if err := loadModule("nvidia", nvidiaOpts); err != nil {
		return fmt.Errorf("loading nvidia driver: %w", err)
	}

	// Wait for driver initialization
	slog.Info("waiting for driver initialization")
	// time.Sleep(5 * time.Second) // TODO: implement proper wait

	// Start NVIDIA services via systemd
	if info.IsMultiGPU {
		if err := startSystemdUnit("nvidia-fabricmanager.service"); err != nil {
			return fmt.Errorf("starting fabric manager: %w", err)
		}
	}

	if err := startSystemdUnit("nvidia-persistenced.service"); err != nil {
		return fmt.Errorf("starting persistenced: %w", err)
	}

	return nil
}

// loadModule loads a kernel module with optional parameters
func loadModule(name, params string) error {
	args := []string{"--ignore-install", name}
	if params != "" {
		args = append(args, params)
	}

	slog.Debug("loading kernel module", "module", name, "params", params)

	cmd := exec.Command("modprobe", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("modprobe %s: %w", name, err)
	}

	return nil
}

// verifyGPUAttestation runs the appropriate attestation verification
func verifyGPUAttestation(info *GPUInfo) error {
	// Activate Python virtualenv and run attestation
	// This shells out to Python as the attestation libraries are Python-only

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
