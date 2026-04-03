package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"tinfoil/internal/boot"
	shimconfig "tinfoil/internal/config"
)

func init() {
	log.SetFlags(0)
}

func main() {
	if len(os.Args) > 1 {
		if err := runSubcommand(os.Args[1]); err != nil {
			log.Printf("Failed: %v", err)
			os.Exit(1)
		}
		return
	}

	log.Println("Tinfoil boot starting")

	if err := run(); err != nil {
		log.Printf("Boot failed: %v", err)
		os.Exit(1)
	}

	log.Println("Tinfoil boot complete")
}

func runSubcommand(cmd string) error {
	switch cmd {
	case "containers", "models":
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
	tracker := boot.NewTracker(boot.InitialStages)

	// 1. Config
	start := time.Now()
	log.Println("Loading configuration")
	config, err := loadAndVerifyConfig()
	if err != nil {
		tracker.Record("config", boot.StatusFailed, time.Since(start), err.Error())
		return err
	}
	externalConfig, err := getExternalConfig()
	if err != nil {
		log.Printf("Warning: external config not available, using defaults: %v", err)
		externalConfig = &shimconfig.ExternalConfig{}
	}
	tracker.Record("config", boot.StatusOK, time.Since(start), "")

	// 2. Identity
	start = time.Now()
	log.Println("Generating node identity")
	nodeID, err := generateIdentity(config.ShimCfg, externalConfig)
	if err != nil {
		tracker.Record("identity", boot.StatusFailed, time.Since(start), err.Error())
		return err
	}
	tracker.Record("identity", boot.StatusOK, time.Since(start), nodeID.Domain)

	// 3. CPU attestation
	start = time.Now()
	log.Println("Fetching CPU attestation")
	cpuAtt, err := fetchCPUAttestation(nodeID, config.ShimCfg)
	if err != nil {
		tracker.Record("cpu-attestation", boot.StatusFailed, time.Since(start), err.Error())
		return err
	}
	tracker.Record("cpu-attestation", boot.StatusOK, time.Since(start), string(cpuAtt.V2Doc.Format))

	// 4. GPU attestation
	start = time.Now()
	gpuCount := config.GPUs
	if gpuCount == 0 {
		var err error
		gpuCount, err = detectGPUCount()
		if err != nil {
			tracker.Record("gpu-attestation", boot.StatusFailed, time.Since(start), err.Error())
			return err
		}
		if gpuCount > 0 {
			log.Printf("GPUs not set in config, detected %d from hardware", gpuCount)
		}
	}
	var gpuEvidence *GPURawEvidence
	if gpuCount > 0 && config.ShimCfg.DummyAttestation {
		log.Printf("Skipping GPU attestation for %d GPUs (dummy-attestation mode)", gpuCount)
		gpuEvidence = dummyGPUEvidence(gpuCount)
		if err := setGPUReadyState(true); err != nil {
			log.Printf("Warning: failed to set GPU ready state: %v", err)
		}
		tracker.Record("gpu-attestation", boot.StatusSkipped, time.Since(start), fmt.Sprintf("%d GPUs (dummy)", gpuCount))
	} else if gpuCount > 0 {
		log.Printf("Verifying GPU attestation (%d GPUs)", gpuCount)
		var err error
		gpuEvidence, err = verifyGPUAttestation(gpuCount)
		if err != nil {
			tracker.Record("gpu-attestation", boot.StatusFailed, time.Since(start), err.Error())
			return err
		}
		tracker.Record("gpu-attestation", boot.StatusOK, time.Since(start), fmt.Sprintf("%d GPUs", gpuCount))
	} else {
		tracker.Record("gpu-attestation", boot.StatusSkipped, time.Since(start), "no GPUs")
	}

	// Write V3 attestation (CPU + GPU raw evidence, no gzip)
	if cpuAtt.RawReport != nil {
		if err := writeAttestationV3(cpuAtt, gpuEvidence); err != nil {
			log.Printf("Warning: failed to write V3 attestation: %v", err)
		}
	}

	// 5. Certificate
	start = time.Now()
	log.Println("Obtaining TLS certificate")
	if err := obtainCertificate(nodeID, cpuAtt.V2Doc, config.ShimCfg, externalConfig); err != nil {
		tracker.Record("certificate", boot.StatusFailed, time.Since(start), err.Error())
		return fmt.Errorf("certificate acquisition failed: %w", err)
	}
	tracker.Record("certificate", boot.StatusOK, time.Since(start), "")

	// 6. Registry auth
	start = time.Now()
	log.Println("Setting up registry authentication")
	if err := setupRegistryAuth(); err != nil {
		log.Printf("Warning: registry auth setup failed: %v", err)
		tracker.Record("registry-auth", boot.StatusWarning, time.Since(start), err.Error())
	} else {
		tracker.Record("registry-auth", boot.StatusOK, time.Since(start), "")
	}

	// 7. Firewall
	start = time.Now()
	log.Println("Configuring firewall")
	if err := setupFirewall(config); err != nil {
		log.Printf("Warning: firewall setup failed: %v", err)
		tracker.Record(boot.StageFirewall, boot.StatusWarning, time.Since(start), err.Error())
	} else {
		tracker.Record(boot.StageFirewall, boot.StatusOK, time.Since(start), "")
	}

	// 8. Models
	start = time.Now()
	log.Println("Mounting models")
	if err := mountModels(config); err != nil {
		log.Printf("Warning: model mount failed: %v", err)
		tracker.Record("models", boot.StatusWarning, time.Since(start), err.Error())
	} else {
		tracker.Record("models", boot.StatusOK, time.Since(start), "")
	}

	// 9. Containers + health checks
	log.Println("Launching containers")
	if err := launchContainersAndWaitHealthy(tracker, config); err != nil {
		return err
	}

	return nil
}
