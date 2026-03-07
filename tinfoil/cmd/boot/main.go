package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"tinfoil/internal/boot"
)

func init() {
	log.SetFlags(0) // No timestamp prefix
}

func main() {
	if len(os.Args) > 1 {
		// Subcommand mode: run individual step for debugging
		if err := runSubcommand(os.Args[1]); err != nil {
			log.Printf("Failed: %v", err)
			os.Exit(1)
		}
		return
	}

	// Normal boot sequence
	log.Println("Tinfoil boot starting")

	if err := run(); err != nil {
		log.Printf("Boot failed: %v", err)
		os.Exit(1)
	}

	log.Println("Tinfoil boot complete")
}

// runSubcommand runs a single step using config from ramdisk (for debugging)
func runSubcommand(cmd string) error {
	// Validate command first
	switch cmd {
	case "containers", "models":
		// Valid command
	default:
		return fmt.Errorf("unknown command: %s\nUsage: tinfoil-boot [containers|models]", cmd)
	}

	config, err := loadConfigFromRamdisk()
	if err != nil {
		return fmt.Errorf("loading config from ramdisk: %w", err)
	}

	switch cmd {
	case "containers":
		log.Println("Setting up registry authentication")
		if err := setupRegistryAuth(); err != nil {
			log.Printf("Warning: registry auth setup failed: %v", err)
		}
		log.Println("Launching containers")
		return launchContainers(config)
	case "models":
		log.Println("Mounting models")
		return mountModels(config)
	}
	return nil
}

func run() error {
	tracker := boot.NewTracker()
	defer func() {
		if err := tracker.Write(); err != nil {
			log.Printf("Warning: failed to write boot state: %v", err)
		}
	}()

	start := time.Now()
	log.Println("Detecting GPUs")
	gpuInfo, err := detectGPUs()
	if err != nil {
		return err
	}

	if gpuInfo.HasNvidia {
		log.Println("Verifying GPU attestation")
		if err := verifyGPUAttestation(gpuInfo); err != nil {
			tracker.Record("gpu-attestation", boot.StatusFailed, time.Since(start), err.Error())
			return err
		}
		tracker.Record("gpu-attestation", boot.StatusOK, time.Since(start), fmt.Sprintf("%d devices", gpuInfo.DeviceCount))
	} else {
		tracker.Record("gpu-attestation", boot.StatusSkipped, time.Since(start), "no GPUs detected")
	}

	start = time.Now()
	log.Println("Loading configuration")
	config, err := loadAndVerifyConfig()
	if err != nil {
		tracker.Record("config", boot.StatusFailed, time.Since(start), err.Error())
		return err
	}
	tracker.Record("config", boot.StatusOK, time.Since(start), "")

	start = time.Now()
	log.Println("Initializing crypto and certificates")
	externalConfig, err := getExternalConfig()
	if err != nil {
		log.Printf("Warning: external config not available, using defaults: %v", err)
		externalConfig = &ExternalConfig{}
	}
	if err := initCrypto(config, externalConfig); err != nil {
		tracker.Record("certificates", boot.StatusFailed, time.Since(start), err.Error())
		return fmt.Errorf("crypto/certificates initialization failed: %w", err)
	}
	tracker.Record("certificates", boot.StatusOK, time.Since(start), "")

	start = time.Now()
	log.Println("Setting up registry authentication")
	if err := setupRegistryAuth(); err != nil {
		log.Printf("Warning: registry auth setup failed: %v", err)
		tracker.Record("registry-auth", boot.StatusWarning, time.Since(start), err.Error())
	} else {
		tracker.Record("registry-auth", boot.StatusOK, time.Since(start), "")
	}

	start = time.Now()
	log.Println("Mounting models")
	if err := mountModels(config); err != nil {
		log.Printf("Warning: model mount failed: %v", err)
		tracker.Record("models", boot.StatusWarning, time.Since(start), err.Error())
	} else {
		tracker.Record("models", boot.StatusOK, time.Since(start), "")
	}

	start = time.Now()
	log.Println("Launching containers")
	if err := launchContainers(config); err != nil {
		log.Printf("Warning: container launch failed: %v", err)
		tracker.Record("containers", boot.StatusWarning, time.Since(start), err.Error())
	} else {
		tracker.Record("containers", boot.StatusOK, time.Since(start), "")
	}

	start = time.Now()
	log.Println("Writing shim config")
	if err := writeShimConfig(config); err != nil {
		tracker.Record("shim-config", boot.StatusFailed, time.Since(start), err.Error())
		return err
	}
	tracker.Record("shim-config", boot.StatusOK, time.Since(start), "")

	return nil
}
