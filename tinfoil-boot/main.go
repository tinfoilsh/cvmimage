package main

import (
	"log/slog"
	"os"
)

func init() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})))
}

func main() {
	slog.Info("tinfoil boot starting")

	if err := run(); err != nil {
		slog.Error("boot failed", "error", err)
		os.Exit(1)
	}

	slog.Info("tinfoil boot complete")
}

func run() error {
	slog.Info("detecting GPUs")
	gpuInfo, err := detectGPUs()
	if err != nil {
		return err
	}

	if gpuInfo.HasNvidia {
		slog.Info("verifying GPU attestation")
		if err := verifyGPUAttestation(gpuInfo); err != nil {
			return err
		}
	} else {
		slog.Info("no GPUs detected")
	}

	slog.Info("loading configuration")
	config, err := loadAndVerifyConfig()
	if err != nil {
		return err
	}

	slog.Info("setting up cloud authentication")
	if err := setupCloudAuth(); err != nil {
		// Non-fatal
		slog.Warn("cloud auth setup failed", "error", err)
	}

	slog.Info("mounting models")
	if err := mountModels(config); err != nil {
		return err
	}

	slog.Info("launching containers")
	if err := launchContainers(config); err != nil {
		return err
	}

	slog.Info("installing tfshim")
	if err := installShim(config); err != nil {
		return err
	}

	return nil
}
