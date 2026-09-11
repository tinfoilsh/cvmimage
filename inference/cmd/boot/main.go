package main

import (
	"fmt"
	"log"
	"time"
	containersecrets "tinfoil/inference/internal/secrets"

	"tinfoil/boot"
	"tinfoil/inference/internal/gpuattestation"
	"tinfoil/inference/internal/nvidia"
	"tinfoil/inference/internal/variant"
	"tinfoil/internal/bootstate"
	"tinfoil/internal/runtimeconfig"
)

func bootSpec() boot.Spec {
	return boot.Spec{
		Stages:          variant.BootStages(),
		Validate:        validate,
		AttestDevices:   attestDevices,
		IsolateModel:    runtimeconfig.ModelIsIsolated,
		WorkloadSecrets: containersecrets.References,
		PrepareWorkload: prepareWorkload,
		DeviceEvidence:  gpuattestation.CollectDeviceEvidence,
	}
}

func main() { boot.Main(bootSpec()) }

func validate(config *boot.Config) error {
	if err := validateGPUCount(config.GPUs); err != nil {
		return err
	}
	if len(config.Volumes) != 0 {
		return fmt.Errorf("volumes are not supported by the inference image")
	}
	return nil
}

func attestDevices(tracker *bootstate.Tracker, config *boot.Config) error {
	start := time.Now()
	gpuCount := config.GPUs
	if err := validateGPUAttestationBootstrap(variant.NVIDIABootstrapStatusPath, config); err != nil {
		wrapped := fmt.Errorf("NVIDIA bootstrap status: %w", err)
		tracker.Record("gpu-attestation", bootstate.StatusFailed, time.Since(start), wrapped.Error())
		return wrapped
	}
	if gpuCount > 0 && config.ShimCfg.DummyAttestation {
		log.Printf("Skipping GPU attestation for %d GPUs (dummy-attestation mode)", gpuCount)
		if err := setGPUReadyState(true); err != nil {
			log.Printf("Warning: failed to set GPU ready state: %v", err)
		}
		tracker.Record("gpu-attestation", bootstate.StatusSkipped, time.Since(start), fmt.Sprintf("%d GPUs (dummy)", gpuCount))
	} else if gpuCount > 0 {
		log.Printf("Verifying GPU attestation (%d GPUs)", gpuCount)
		var err error
		_, err = verifyGPUAttestation(gpuCount)
		if err != nil {
			tracker.Record("gpu-attestation", bootstate.StatusFailed, time.Since(start), err.Error())
			return err
		}
		tracker.Record("gpu-attestation", bootstate.StatusOK, time.Since(start), fmt.Sprintf("%d GPUs", gpuCount))
	} else {
		tracker.Record("gpu-attestation", bootstate.StatusSkipped, time.Since(start), "no GPUs")
	}
	return nil
}

func validateGPUAttestationBootstrap(path string, config *boot.Config) error {
	if config == nil || config.ShimCfg == nil {
		return fmt.Errorf("GPU attestation config is incomplete")
	}
	return nvidia.ValidateBootstrapStatus(path, config.GPUs)
}

const maxGPUCount = 8

func validateGPUCount(count int) error {
	if count < 0 || count > maxGPUCount {
		return fmt.Errorf("gpus must be between 0 and %d (got %d)", maxGPUCount, count)
	}
	return nil
}
