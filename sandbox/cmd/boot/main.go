package main

import (
	"fmt"

	"tinfoil/boot"
	"tinfoil/internal/attestation"
	"tinfoil/sandbox/internal/variant"
)

func bootSpec() boot.Spec {
	return boot.Spec{
		Stages:         variant.BootStages(),
		Validate:       validate,
		IsolateModel:   func(*boot.Config, string) bool { return true },
		DeviceEvidence: attestation.NoDeviceEvidence,
	}
}

func main() { boot.Main(bootSpec()) }

func validate(config *boot.Config) error {
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
