package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"tinfoil/internal/boot"
	shimconfig "tinfoil/internal/config"
	"tinfoil/internal/device"
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

	bootLogf("Tinfoil boot starting")

	if err := run(); err != nil {
		bootLogf("Boot failed: %v", err)
		maybeDropToDebugFailureShell(err)
		os.Exit(1)
	}

	bootLogf("Tinfoil boot complete")
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
		externalConfig, err := getExternalConfig()
		if err != nil {
			log.Printf("Warning: external config not available, using defaults: %v", err)
			externalConfig = &shimconfig.ExternalConfig{}
		}
		// Manual re-run must fetch vault secrets, they're not persisted on disk.
		if config.VaultURL != "" {
			log.Println("Fetching vault secrets")
			if err := fetchVaultSecrets(config, externalConfig); err != nil {
				return fmt.Errorf("vault secret fetch failed: %w", err)
			}
		}
		log.Println("Setting up registry authentication")
		if err := setupRegistryAuth(); err != nil {
			log.Printf("Warning: registry auth setup failed: %v", err)
		}
		log.Println("Launching containers")
		return launchContainers(config, externalConfig)
	case "models":
		externalConfig, err := getExternalConfig()
		if err != nil {
			log.Printf("Warning: external config not available, using defaults: %v", err)
			externalConfig = &shimconfig.ExternalConfig{}
		}
		log.Println("Mounting models")
		return mountModels(config, externalConfig)
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

	// 2. Device permissions
	start = time.Now()
	log.Println("Setting required device permissions")
	if err := device.SetupRequiredPermissions(); err != nil {
		if config.GPUs > 0 {
			tracker.Record(boot.StageDeviceSetup, boot.StatusFailed, time.Since(start), err.Error())
			return fmt.Errorf("device setup failed: %w", err)
		}
		log.Printf("Warning: device permission setup incomplete: %v", err)
		tracker.Record(boot.StageDeviceSetup, boot.StatusWarning, time.Since(start), err.Error())
	} else {
		tracker.Record(boot.StageDeviceSetup, boot.StatusOK, time.Since(start), "")
	}

	// 3. Identity
	start = time.Now()
	log.Println("Generating node identity")
	nodeID, err := generateIdentity(config.ShimCfg, externalConfig)
	if err != nil {
		tracker.Record("identity", boot.StatusFailed, time.Since(start), err.Error())
		return err
	}
	tracker.Record("identity", boot.StatusOK, time.Since(start), nodeID.Domain)

	// 4. CPU attestation
	start = time.Now()
	log.Println("Fetching CPU attestation")
	cpuAtt, err := fetchCPUAttestation(nodeID, config.ShimCfg)
	if err != nil {
		tracker.Record("cpu-attestation", boot.StatusFailed, time.Since(start), err.Error())
		return err
	}
	tracker.Record("cpu-attestation", boot.StatusOK, time.Since(start), string(cpuAtt.V2Doc.Format))

	// 5. Network readiness
	start = time.Now()
	bootLogf("Waiting for guest network")
	networkDetail, err := waitForNetworkReady(context.Background())
	if err != nil {
		tracker.Record(boot.StageNetwork, boot.StatusFailed, time.Since(start), err.Error())
		return fmt.Errorf("network readiness failed: %w", err)
	}
	bootLogf("Guest network ready: %s", networkDetail)
	tracker.Record(boot.StageNetwork, boot.StatusOK, time.Since(start), networkDetail)

	// 6. GPU attestation
	start = time.Now()
	gpuCount := config.GPUs
	if gpuCount == 0 {
		detected, err := detectGPUCount()
		if err != nil {
			tracker.Record("gpu-attestation", boot.StatusFailed, time.Since(start), err.Error())
			return err
		}
		if detected > 0 {
			tracker.Record("gpu-attestation", boot.StatusFailed, time.Since(start),
				fmt.Sprintf("detected %d GPU(s) but config declares gpus: 0 — set the correct gpu count in the config", detected))
			return fmt.Errorf("gpu count mismatch: detected %d, config says 0", detected)
		}
	}
	if gpuCount > 0 && config.ShimCfg.DummyAttestation {
		log.Printf("Skipping GPU attestation for %d GPUs (dummy-attestation mode)", gpuCount)
		if err := setGPUReadyState(true); err != nil {
			log.Printf("Warning: failed to set GPU ready state: %v", err)
		}
		tracker.Record("gpu-attestation", boot.StatusSkipped, time.Since(start), fmt.Sprintf("%d GPUs (dummy)", gpuCount))
	} else if gpuCount > 0 {
		log.Printf("Verifying GPU attestation (%d GPUs)", gpuCount)
		var err error
		_, err = verifyGPUAttestation(gpuCount)
		if err != nil {
			tracker.Record("gpu-attestation", boot.StatusFailed, time.Since(start), err.Error())
			return err
		}
		tracker.Record("gpu-attestation", boot.StatusOK, time.Since(start), fmt.Sprintf("%d GPUs", gpuCount))
	} else {
		tracker.Record("gpu-attestation", boot.StatusSkipped, time.Since(start), "no GPUs")
	}

	// 7. Certificate
	start = time.Now()
	log.Println("Obtaining TLS certificate")
	if err := obtainCertificate(nodeID, cpuAtt.V2Doc, config.ShimCfg, externalConfig); err != nil {
		tracker.Record("certificate", boot.StatusFailed, time.Since(start), err.Error())
		return fmt.Errorf("certificate acquisition failed: %w", err)
	}
	tracker.Record("certificate", boot.StatusOK, time.Since(start), "")

	// 8. Fetch any external vault secrets.
	start = time.Now()
	if config.VaultURL == "" {
		tracker.Record(boot.StageVaultSecrets, boot.StatusSkipped, time.Since(start), "no vault configured")
	} else {
		log.Println("Fetching vault secrets")
		if err := fetchVaultSecrets(config, externalConfig); err != nil {
			tracker.Record(boot.StageVaultSecrets, boot.StatusFailed, time.Since(start), err.Error())
			return fmt.Errorf("vault secret fetch failed: %w", err)
		}
		tracker.Record(boot.StageVaultSecrets, boot.StatusOK, time.Since(start), config.VaultURL)
	}

	// 9. Registry auth
	start = time.Now()
	log.Println("Setting up registry authentication")
	if err := setupRegistryAuth(); err != nil {
		log.Printf("Warning: registry auth setup failed: %v", err)
		tracker.Record("registry-auth", boot.StatusWarning, time.Since(start), err.Error())
	} else {
		tracker.Record("registry-auth", boot.StatusOK, time.Since(start), "")
	}

	// 10. Firewall
	start = time.Now()
	log.Println("Configuring firewall")
	if err := setupFirewall(config); err != nil {
		tracker.Record(boot.StageFirewall, boot.StatusFailed, time.Since(start), err.Error())
		return fmt.Errorf("firewall setup failed: %w", err)
	}
	tracker.Record(boot.StageFirewall, boot.StatusOK, time.Since(start), "")

	// 11. Models
	start = time.Now()
	log.Println("Mounting models")
	if err := mountModels(config, externalConfig); err != nil {
		tracker.Record("models", boot.StatusFailed, time.Since(start), err.Error())
		return fmt.Errorf("model mount failed: %w", err)
	}
	tracker.Record("models", boot.StatusOK, time.Since(start), "")

	// 12. Containers + health checks
	log.Println("Launching containers")
	if err := launchContainersAndWaitHealthy(tracker, config, externalConfig); err != nil {
		return err
	}

	return nil
}
