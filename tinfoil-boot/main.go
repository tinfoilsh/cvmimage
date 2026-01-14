package main

import (
	"log/slog"
	"os"
)

func main() {
	slog.Info("tinfoil boot starting")

	if err := run(); err != nil {
		slog.Error("boot failed", "error", err)
		os.Exit(1)
	}

	slog.Info("tinfoil boot complete")
}

func run() error {
	// Step 1: Create and mount ramdisk
	slog.Info("creating ramdisk")
	if err := setupRamdisk(); err != nil {
		return err
	}

	// Step 2: Detect and initialize GPUs
	slog.Info("detecting GPUs")
	gpuInfo, err := detectGPUs()
	if err != nil {
		return err
	}

	if gpuInfo.HasNvidia {
		slog.Info("initializing NVIDIA GPUs")
		if err := initializeNvidiaGPUs(gpuInfo); err != nil {
			return err
		}

		slog.Info("verifying GPU attestation")
		if err := verifyGPUAttestation(gpuInfo); err != nil {
			return err
		}
	} else {
		slog.Info("no NVIDIA GPUs detected, skipping initialization")
	}

	// Step 3: Load and verify config
	slog.Info("loading configuration")
	config, err := loadAndVerifyConfig()
	if err != nil {
		return err
	}

	// Step 4: Setup cloud authentication
	slog.Info("setting up cloud authentication")
	if err := setupCloudAuth(); err != nil {
		// Non-fatal - external config may not exist
		slog.Warn("cloud auth setup failed", "error", err)
	}

	// Step 5: Mount model packs
	slog.Info("mounting models")
	if err := mountModels(config); err != nil {
		return err
	}

	// Step 6: Launch containers
	slog.Info("launching containers")
	if err := launchContainers(config); err != nil {
		return err
	}

	// Step 7: Install and start tfshim
	slog.Info("installing and starting tfshim")
	if err := installAndStartShim(config); err != nil {
		return err
	}

	return nil
}
