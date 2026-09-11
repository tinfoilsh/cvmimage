package main

import (
	"fmt"
	"path/filepath"

	runtimeconfig "github.com/tinfoilsh/tinfoil-config"

	"tinfoil/boot"
	"tinfoil/internal/attestation"
	"tinfoil/internal/bootstate"
	"tinfoil/internal/modelpack"
	"tinfoil/sandbox/internal/variant"
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
		mounts = append(mounts, modelpack.Mount{
			Model: model, Disk: index, Target: filepath.Join(bootstate.PrivateModelsDir, model.Name),
		})
	}
	return boot.Workload{Mounts: mounts, DeviceEvidence: attestation.NoDeviceEvidence}, nil
}

func validate(config *runtimeconfig.Config) error {
	if config.GPUs != 0 {
		return fmt.Errorf("gpus are not supported by the sandbox image")
	}
	if len(config.Containers) != 0 {
		return fmt.Errorf("containers are not supported by the sandbox image")
	}
	if len(config.Volumes) != 1 {
		return fmt.Errorf("the sandbox image takes exactly one volume, got %d", len(config.Volumes))
	}
	return nil
}
