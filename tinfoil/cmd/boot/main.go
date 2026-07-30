package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"tinfoil/internal/boot"
	"tinfoil/internal/containersapi"
	"tinfoil/internal/nvidia"
)

func init() {
	log.SetFlags(0)
}

func main() {
	if err := validateInvocation(os.Args); err != nil {
		log.Printf("Failed: %v", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	log.Println("Tinfoil boot starting")

	if err := run(ctx); err != nil {
		log.Printf("Boot failed: %v", err)
		os.Exit(1)
	}

	log.Println("Tinfoil boot complete")
}

func validateInvocation(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("tinfoil-boot does not accept arguments; reboot or redeploy to relaunch containers or remount models")
	}
	return nil
}

func run(ctx context.Context) error {
	tracker := boot.NewTracker(boot.InitialStages)

	// 1. Config
	start := time.Now()
	log.Println("Loading configuration")
	cmdline, err := readKernelCmdline()
	if err != nil {
		tracker.Record("config", boot.StatusFailed, time.Since(start), err.Error())
		return fmt.Errorf("parsing kernel cmdline: %w", err)
	}
	config, err := loadAndVerifyConfig(cmdline)
	if err != nil {
		tracker.Record("config", boot.StatusFailed, time.Since(start), err.Error())
		return err
	}
	externalConfig, err := getExternalConfig()
	if err != nil {
		tracker.Record("config", boot.StatusFailed, time.Since(start), err.Error())
		return fmt.Errorf("loading external config: %w", err)
	}
	tracker.Record("config", boot.StatusOK, time.Since(start), "")

	// 2. Network
	start = time.Now()
	log.Println("Configuring guest network")
	networkDetail, err := configureGuestNetwork(ctx, externalConfig.Network)
	if err != nil {
		tracker.Record(boot.StageNetwork, boot.StatusFailed, time.Since(start), err.Error())
		return fmt.Errorf("network configuration failed: %w", err)
	}
	tracker.Record(boot.StageNetwork, boot.StatusOK, time.Since(start), networkDetail)

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

	// 5. GPU attestation
	start = time.Now()
	gpuCount := config.GPUs
	if err := validateGPUAttestationBootstrap(boot.NVIDIABootstrapStatusPath, config); err != nil {
		wrapped := fmt.Errorf("NVIDIA bootstrap status: %w", err)
		tracker.Record("gpu-attestation", boot.StatusFailed, time.Since(start), wrapped.Error())
		return wrapped
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

	// 6. Certificate
	start = time.Now()
	log.Println("Obtaining TLS certificate")
	if err := obtainCertificate(nodeID, cpuAtt.V2Doc, config.ShimCfg, externalConfig); err != nil {
		tracker.Record("certificate", boot.StatusFailed, time.Since(start), err.Error())
		return fmt.Errorf("certificate acquisition failed: %w", err)
	}
	tracker.Record("certificate", boot.StatusOK, time.Since(start), "")

	// 7. Fetch any external vault secrets.
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

	// 8. Registry auth
	start = time.Now()
	log.Println("Setting up registry authentication")
	if err := setupRegistryAuth(externalConfig); err != nil {
		tracker.Record("registry-auth", boot.StatusFailed, time.Since(start), err.Error())
		return fmt.Errorf("registry auth setup failed: %w", err)
	}
	tracker.Record("registry-auth", boot.StatusOK, time.Since(start), "")

	// 9. Models
	start = time.Now()
	log.Println("Mounting models")
	if err := mountModels(config, externalConfig); err != nil {
		tracker.Record("models", boot.StatusFailed, time.Since(start), err.Error())
		return fmt.Errorf("model mount failed: %w", err)
	}
	tracker.Record("models", boot.StatusOK, time.Since(start), "")

	// 10. Install runtime configuration and launch containers
	start = time.Now()
	log.Println("Launching containers")
	if err := containersapi.Boot(ctx, nil); err != nil {
		tracker.Record(boot.StageContainers, boot.StatusFailed, time.Since(start), err.Error())
		return err
	}
	tracker.Record(boot.StageContainers, boot.StatusOK, time.Since(start), "")

	return nil
}

func validateGPUAttestationBootstrap(path string, config *Config) error {
	if config == nil || config.ShimCfg == nil {
		return fmt.Errorf("GPU attestation config is incomplete")
	}
	return nvidia.ValidateBootstrapStatus(path, config.GPUs)
}
