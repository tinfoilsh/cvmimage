//go:build !tinfoil_gpu

package main

import (
	"fmt"
	"time"
	"tinfoil/internal/boot"
)

func attestGPU(config *Config, record func(string, string, time.Duration, string)) error {
	if config.GPUs != 0 {
		err := fmt.Errorf("CPU runtime does not support GPUs")
		record(boot.StageGPUAttestation, boot.StatusFailed, 0, err.Error())
		return err
	}
	record("gpu-attestation", boot.StatusSkipped, 0, "CPU runtime")
	return nil
}
