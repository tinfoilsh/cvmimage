//go:build !tinfoil_gpu

package main

import (
	"fmt"
	"tinfoil/internal/boot"
)

func attestGPU(config *Config, tracker *boot.Tracker) error {
	if config.GPUs != 0 {
		return fmt.Errorf("CPU runtime does not support GPUs")
	}
	tracker.Record("gpu-attestation", boot.StatusSkipped, 0, "CPU runtime")
	return nil
}
