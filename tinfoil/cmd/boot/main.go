package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"tinfoil/internal/boot"
	"tinfoil/internal/nvidia"
)

func init() {
	log.SetFlags(0)
}

func main() {
	invocation, err := parseInvocation(os.Args)
	if err != nil {
		log.Printf("Failed: %v", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	log.Println("Tinfoil boot starting")

	if err := run(ctx, invocation); err != nil {
		log.Printf("Boot failed: %v", err)
		os.Exit(1)
	}

	log.Println("Tinfoil boot complete")
}

type invocation struct {
	configHash string
	debug      bool
	secretsFD  int
}

func parseInvocation(args []string) (invocation, error) {
	if len(args) == 0 {
		return invocation{}, fmt.Errorf("missing argv[0]")
	}
	var parsed invocation
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&parsed.configHash, "config-hash", "", "verified config hash from the kernel command line")
	flags.BoolVar(&parsed.debug, "debug", false, "enable the measured debug policy")
	flags.IntVar(&parsed.secretsFD, "secrets-fd", -1, "sealed container-secret handoff descriptor")
	if err := flags.Parse(args[1:]); err != nil {
		return invocation{}, err
	}
	if flags.NArg() != 0 {
		return invocation{}, fmt.Errorf("tinfoil-boot does not accept maintenance commands")
	}
	return parsed, nil
}

func run(ctx context.Context, invocation invocation) error {
	if invocation.secretsFD < 0 {
		return fmt.Errorf("container-secret handoff descriptor is required")
	}
	secretHandoff := os.NewFile(uintptr(invocation.secretsFD), "tinfoil-container-secrets")
	defer secretHandoff.Close()

	tracker := boot.NewTracker(boot.InitialStages)

	// 1. Config
	start := time.Now()
	log.Println("Loading configuration")
	config, err := loadAndVerifyConfig(invocation.configHash, invocation.debug)
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
	collateralRequest, err := writeCollateralRequest(boot.CollateralRequestPath, cpuAtt, externalConfig)
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

	// 7. Resolve declared secrets and hand workload values to the container manager.
	start = time.Now()
	secretDetail, err := prepareSecretHandoff(ctx, config, externalConfig, secretHandoff, invocation.configHash, nodeID, collateralRequest)
	if err != nil {
		tracker.Record(boot.StageKBSSecrets, boot.StatusFailed, time.Since(start), err.Error())
		return err
	}
	tracker.Record(boot.StageKBSSecrets, boot.StatusOK, time.Since(start), secretDetail)

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

	return nil
}

func validateGPUAttestationBootstrap(path string, config *Config) error {
	if config == nil || config.ShimCfg == nil {
		return fmt.Errorf("GPU attestation config is incomplete")
	}
	return nvidia.ValidateBootstrapStatus(path, config.GPUs)
}
