package main

import (
	"fmt"
	"log"
	"os"
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
	case "containers", "shim", "models":
		// Valid command
	default:
		return fmt.Errorf("unknown command: %s\nUsage: tinfoil-boot [containers|shim|models]", cmd)
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
	case "shim":
		log.Println("Installing tfshim")
		return installShim(config)
	case "models":
		log.Println("Mounting models")
		return mountModels(config)
	}
	return nil
}

func run() error {
	log.Println("Detecting GPUs")
	gpuInfo, err := detectGPUs()
	if err != nil {
		return err
	}

	if gpuInfo.HasNvidia {
		log.Println("Verifying GPU attestation")
		if err := verifyGPUAttestation(gpuInfo); err != nil {
			return err
		}
	} else {
		log.Println("No GPUs detected")
	}

	log.Println("Loading configuration")
	config, err := loadAndVerifyConfig()
	if err != nil {
		return err
	}

	log.Println("Setting up registry authentication")
	if err := setupRegistryAuth(); err != nil {
		log.Printf("Warning: registry auth setup failed: %v", err)
	}

	log.Println("Mounting models")
	if err := mountModels(config); err != nil {
		return err
	}

	log.Println("Launching containers")
	if err := launchContainers(config); err != nil {
		return err
	}

	log.Println("Installing tfshim")
	if err := installShim(config); err != nil {
		return err
	}

	return nil
}
