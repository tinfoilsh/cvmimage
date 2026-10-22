//go:build tinfoil_gpu

package main

import (
	"fmt"
	"log"
	"time"
	"tinfoil/internal/boot"
	"tinfoil/internal/nvidia"
)

func attestGPU(config *Config, tracker *boot.Tracker) error {
	// 5. GPU attestation
	start := time.Now()
	gpuCount := config.GPUs
	if err := validateGPUAttestationBootstrap(boot.NVIDIABootstrapStatusPath, config); err != nil {
		wrapped := fmt.Errorf("NVIDIA bootstrap status: %w", err)
		tracker.Record("gpu-attestation", boot.StatusFailed, time.Since(start), wrapped.Error())
		return wrapped
	}
	var gpuArch string
	if gpuCount > 0 {
		deviceIDs, err := nvidia.GPUDeviceIDs()
		if err == nil {
			gpuArch, err = validateGPUSecurity(deviceIDs, gpuCount, config.Security.AllowUnencryptedNVLink)
		}
		if err != nil {
			if readyErr := setGPUReadyState(false); readyErr != nil {
				log.Printf("WARNING: failed to disable GPU ready state: %v", readyErr)
			}
			tracker.Record("gpu-attestation", boot.StatusFailed, time.Since(start), err.Error())
			return err
		}
	}
	if gpuCount > 0 && config.ShimCfg.DummyAttestation {
		log.Printf("Skipping GPU attestation for %d GPUs (dummy-attestation mode)", gpuCount)
		if err := setGPUReadyState(true); err != nil {
			log.Printf("Warning: failed to set GPU ready state: %v", err)
		}
		tracker.Record("gpu-attestation", boot.StatusSkipped, time.Since(start), fmt.Sprintf("%d GPUs (dummy)", gpuCount))
	} else if gpuCount > 0 {
		log.Printf("Verifying GPU attestation (%d GPUs)", gpuCount)
		var err error
		_, err = verifyGPUAttestation(gpuCount, gpuArch)
		if err != nil {
			tracker.Record("gpu-attestation", boot.StatusFailed, time.Since(start), err.Error())
			return err
		}
		tracker.Record("gpu-attestation", boot.StatusOK, time.Since(start), fmt.Sprintf("%d GPUs", gpuCount))
	} else {
		tracker.Record("gpu-attestation", boot.StatusSkipped, time.Since(start), "no GPUs")
	}

	return nil
}

func validateGPUAttestationBootstrap(path string, config *Config) error {
	if config == nil || config.ShimCfg == nil {
		return fmt.Errorf("GPU attestation config is incomplete")
	}
	return nvidia.ValidateBootstrapStatus(path, config.GPUs)
}
