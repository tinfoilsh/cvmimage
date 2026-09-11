package main

import (
	"fmt"
	"log"
	"path/filepath"
	"time"

	runtimeconfig "github.com/tinfoilsh/tinfoil-config"

	"tinfoil/boot"
	"tinfoil/inference/internal/gpuattestation"
	"tinfoil/inference/internal/nvidia"
	containersecrets "tinfoil/inference/internal/secrets"
	"tinfoil/inference/internal/variant"
	"tinfoil/internal/bootstate"
	shimconfig "tinfoil/internal/config"
	"tinfoil/internal/modelpack"
	"tinfoil/internal/secretstore"
)

func bootSpec() boot.Spec {
	return boot.Spec{Stages: variant.BootStages(), Configure: configureWorkload}
}

func configureWorkload(config *runtimeconfig.Config) (boot.Workload, error) {
	if err := validate(config); err != nil {
		return boot.Workload{}, err
	}
	var mounts []modelpack.Mount
	for index, model := range config.Models {
		isolated := runtimeconfig.ModelIsIsolated(config, model.Name)
		target := filepath.Join(bootstate.PrivateModelsDir, model.Name)
		if !isolated {
			var err error
			target, err = modelpack.PublicTarget(model)
			if err != nil {
				return boot.Workload{}, err
			}
		}
		mounts = append(mounts, modelpack.Mount{Model: model, Disk: index, Target: target, LegacyAlias: !isolated})
	}
	return boot.Workload{
		Mounts:         mounts,
		Secrets:        containersecrets.References(config),
		DeviceEvidence: gpuattestation.Provider(config.GPUs),
		AttestDevices:  func(tracker *bootstate.Tracker) error { return attestDevices(tracker, config) },
		Prepare: func(tracker *bootstate.Tracker, external *shimconfig.ExternalConfig, secrets secretstore.Store) error {
			return prepareWorkload(tracker, mounts, external, secrets)
		},
	}, nil
}

func validate(config *runtimeconfig.Config) error {
	if err := validateGPUCount(config.GPUs); err != nil {
		return err
	}
	if len(config.Volumes) != 0 {
		return fmt.Errorf("volumes are not supported by the inference image")
	}
	return nil
}

func attestDevices(tracker *bootstate.Tracker, config *runtimeconfig.Config) error {
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

func validateGPUAttestationBootstrap(path string, config *runtimeconfig.Config) error {
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
