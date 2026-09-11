package boot

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

	"tinfoil/internal/attestation"
	"tinfoil/internal/bootstate"
	shimconfig "tinfoil/internal/config"
)

// Spec supplies the workload's boot policies. Optional hooks run at the fixed
// device-attestation and workload-preparation points in the platform lifecycle.
type Spec struct {
	Stages          []string
	Validate        func(*Config) error
	AttestDevices   func(*bootstate.Tracker, *Config) error
	IsolateModel    func(*Config, string) bool
	WorkloadSecrets func(*Config) []string
	PrepareWorkload func(*bootstate.Tracker, *Config, *shimconfig.ExternalConfig) error
	DeviceEvidence  attestation.DeviceEvidenceProvider
}

func Main(spec Spec) {
	log.SetFlags(0)
	if spec.Validate == nil || spec.IsolateModel == nil || spec.DeviceEvidence == nil || len(spec.Stages) == 0 {
		log.Fatal("incomplete boot spec")
	}
	invocation, err := parseInvocation(os.Args)
	if err != nil {
		log.Printf("Failed: %v", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	log.Println("Tinfoil boot starting")

	if err := run(ctx, invocation, spec); err != nil {
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
	flags.IntVar(&parsed.secretsFD, "secrets-fd", -1, "sealed workload-secret handoff descriptor")
	if err := flags.Parse(args[1:]); err != nil {
		return invocation{}, err
	}
	if flags.NArg() != 0 {
		return invocation{}, fmt.Errorf("tinfoil-boot does not accept maintenance commands")
	}
	return parsed, nil
}

func run(ctx context.Context, invocation invocation, spec Spec) error {
	if invocation.secretsFD < 0 {
		return fmt.Errorf("workload-secret handoff descriptor is required")
	}
	secretHandoff := os.NewFile(uintptr(invocation.secretsFD), "tinfoil-workload-secrets")
	defer secretHandoff.Close()

	tracker := bootstate.NewTracker(spec.Stages)

	// Config
	start := time.Now()
	log.Println("Loading configuration")
	config, err := loadAndVerifyConfig(invocation.configHash, invocation.debug, spec.Validate)
	if err != nil {
		tracker.Record("config", bootstate.StatusFailed, time.Since(start), err.Error())
		return err
	}
	externalConfig, err := getExternalConfig()
	if err != nil {
		tracker.Record("config", bootstate.StatusFailed, time.Since(start), err.Error())
		return fmt.Errorf("loading external config: %w", err)
	}
	tracker.Record("config", bootstate.StatusOK, time.Since(start), "")

	// Network
	start = time.Now()
	log.Println("Configuring guest network")
	networkDetail, err := configureGuestNetwork(ctx, externalConfig.Network)
	if err != nil {
		tracker.Record(bootstate.StageNetwork, bootstate.StatusFailed, time.Since(start), err.Error())
		return fmt.Errorf("network configuration failed: %w", err)
	}
	tracker.Record(bootstate.StageNetwork, bootstate.StatusOK, time.Since(start), networkDetail)

	// Identity
	start = time.Now()
	log.Println("Generating node identity")
	nodeID, err := generateIdentity(config.ShimCfg, externalConfig)
	if err != nil {
		tracker.Record("identity", bootstate.StatusFailed, time.Since(start), err.Error())
		return err
	}
	tracker.Record("identity", bootstate.StatusOK, time.Since(start), nodeID.Domain)

	// CPU attestation
	start = time.Now()
	log.Println("Fetching CPU attestation")
	cpuAtt, err := fetchCPUAttestation(nodeID, config.ShimCfg)
	if err != nil {
		tracker.Record("cpu-attestation", bootstate.StatusFailed, time.Since(start), err.Error())
		return err
	}
	collateralRequest, err := writeCollateralRequest(bootstate.CollateralRequestPath, cpuAtt, externalConfig)
	if err != nil {
		tracker.Record("cpu-attestation", bootstate.StatusFailed, time.Since(start), err.Error())
		return err
	}
	tracker.Record("cpu-attestation", bootstate.StatusOK, time.Since(start), string(cpuAtt.V2Doc.Format))

	// Optional device attestation
	if spec.AttestDevices != nil {
		if err := spec.AttestDevices(tracker, config); err != nil {
			return err
		}
	}

	// Certificate
	start = time.Now()
	log.Println("Obtaining TLS certificate")
	if err := obtainCertificate(nodeID, cpuAtt.V2Doc, config.ShimCfg, externalConfig); err != nil {
		tracker.Record("certificate", bootstate.StatusFailed, time.Since(start), err.Error())
		return fmt.Errorf("certificate acquisition failed: %w", err)
	}
	tracker.Record("certificate", bootstate.StatusOK, time.Since(start), "")

	// Resolve model keys and the secrets requested by the workload.
	start = time.Now()
	var workloadReferences []string
	if spec.WorkloadSecrets != nil {
		workloadReferences = spec.WorkloadSecrets(config)
	}
	secretDetail, err := prepareSecretHandoff(ctx, config, workloadReferences, externalConfig, secretHandoff, invocation.configHash, invocation.debug,
		func(ctx context.Context, names []string) (map[string]string, error) {
			return fetchKeyserverSecrets(ctx, config, externalConfig, nodeID, collateralRequest, names, spec.DeviceEvidence)
		})
	if err != nil {
		tracker.Record(bootstate.StageKeyserverSecrets, bootstate.StatusFailed, time.Since(start), err.Error())
		return err
	}
	tracker.Record(bootstate.StageKeyserverSecrets, bootstate.StatusOK, time.Since(start), secretDetail)

	if spec.PrepareWorkload != nil {
		if err := spec.PrepareWorkload(tracker, config, externalConfig); err != nil {
			return err
		}
	}

	// Models
	start = time.Now()
	log.Println("Mounting models")
	if err := mountModels(spec.IsolateModel, config, externalConfig); err != nil {
		tracker.Record("models", bootstate.StatusFailed, time.Since(start), err.Error())
		return fmt.Errorf("model mount failed: %w", err)
	}
	tracker.Record("models", bootstate.StatusOK, time.Since(start), "")

	return nil
}
