package main

import (
	"log"
	"os"
)

func init() {
	log.SetFlags(0) // No timestamp prefix
}

func main() {
	log.Println("Tinfoil boot starting")

	if err := run(); err != nil {
		log.Printf("Boot failed: %v", err)
		os.Exit(1)
	}

	log.Println("Tinfoil boot complete")
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

	log.Println("Setting up cloud authentication")
	if err := setupCloudAuth(); err != nil {
		// Non-fatal
		log.Printf("Warning: cloud auth setup failed: %v", err)
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
