package boot

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"tinfoil/internal/attestation"
	"tinfoil/internal/bootstate"
	"tinfoil/internal/guestnet"
	"tinfoil/internal/identity"
	"tinfoil/internal/keyserver"
	"tinfoil/internal/modelpack"
	"tinfoil/internal/secretstore"
	tlsutil "tinfoil/internal/tls"
)

// Run provisions boot artifacts. The caller owns signal handling and exit status.
func Run(ctx context.Context, options Options, spec Spec) error {
	if spec.Configure == nil || len(spec.Stages) == 0 {
		return fmt.Errorf("incomplete boot spec")
	}
	if options.SecretsFD < 0 {
		return fmt.Errorf("workload-secret handoff descriptor is required")
	}
	secretHandoff := os.NewFile(uintptr(options.SecretsFD), "tinfoil-workload-secrets")
	defer secretHandoff.Close()

	tracker := bootstate.NewTracker(spec.Stages)

	// Config
	start := time.Now()
	log.Println("Loading configuration")
	inputs, err := loadInputs(options, spec)
	if err == nil {
		err = publishConfig(inputs)
	}
	if err != nil {
		tracker.Record(bootstate.StageConfig, bootstate.StatusFailed, time.Since(start), err.Error())
		return err
	}
	config, externalConfig, workload := inputs.config, inputs.external, inputs.workload
	tracker.Record(bootstate.StageConfig, bootstate.StatusOK, time.Since(start), "")

	// Network
	start = time.Now()
	log.Println("Configuring guest network")
	networkDetail, err := guestnet.Configure(ctx, externalConfig.Network)
	if err != nil {
		tracker.Record(bootstate.StageNetwork, bootstate.StatusFailed, time.Since(start), err.Error())
		return fmt.Errorf("network configuration failed: %w", err)
	}
	tracker.Record(bootstate.StageNetwork, bootstate.StatusOK, time.Since(start), networkDetail)

	// Identity
	start = time.Now()
	log.Println("Generating node identity")
	nodeID, err := identity.Generate(externalConfig.Env["DOMAIN"], config.ShimCfg.DummyAttestation, bootstate.HPKEKeyPath)
	if err != nil {
		tracker.Record("identity", bootstate.StatusFailed, time.Since(start), err.Error())
		return err
	}
	tracker.Record("identity", bootstate.StatusOK, time.Since(start), nodeID.Domain)

	// CPU attestation
	start = time.Now()
	log.Println("Fetching CPU attestation")
	cpuAtt, err := attestation.CollectCPU(nodeID.Body(), nodeID.Domain == "localhost" || config.ShimCfg.DummyAttestation)
	if err != nil {
		tracker.Record("cpu-attestation", bootstate.StatusFailed, time.Since(start), err.Error())
		return err
	}
	if err := writeAttestationDoc(cpuAtt.V2Doc); err != nil {
		tracker.Record(bootstate.StageCPUAttestation, bootstate.StatusFailed, time.Since(start), err.Error())
		return err
	}
	collateralRequest, err := writeCollateralRequest(bootstate.CollateralRequestPath, cpuAtt, externalConfig)
	if err != nil {
		tracker.Record("cpu-attestation", bootstate.StatusFailed, time.Since(start), err.Error())
		return err
	}
	tracker.Record("cpu-attestation", bootstate.StatusOK, time.Since(start), string(cpuAtt.V2Doc.Format))

	// Optional device attestation
	if workload.AttestDevices != nil {
		if err := workload.AttestDevices(tracker); err != nil {
			return err
		}
	}

	// Certificate
	start = time.Now()
	log.Println("Obtaining TLS certificate")
	cert, err := tlsutil.Provision(ctx, tlsutil.Request{
		Domain: nodeID.Domain, Key: nodeID.TLSKey, HPKEKey: nodeID.HPKEKeyBytes,
		AttestationHash: cpuAtt.V2Doc.Hash(),
	}, config.ShimCfg, secretstore.Store(externalConfig.Secrets))
	if err == nil {
		err = writeTLSArtifacts(cert, nodeID.TLSKey)
	}
	if err != nil {
		tracker.Record(bootstate.StageCertificate, bootstate.StatusFailed, time.Since(start), err.Error())
		return fmt.Errorf("certificate acquisition failed: %w", err)
	}
	tracker.Record(bootstate.StageCertificate, bootstate.StatusOK, time.Since(start), "")

	// Resolve model keys and seal only the workload's requested secrets.
	start = time.Now()
	source := secretstore.Source{Host: secretstore.Store(externalConfig.Secrets), Debug: options.Debug}
	if config.KeyserverURL != "" {
		client := &keyserver.Client{
			URL: config.KeyserverURL, Repo: externalConfig.Metadata.Repo, Certificate: *cert,
			Identity: nodeID.Body(), CollateralRequest: collateralRequest, ATC: config.ShimCfg.ATC,
			Devices: workload.DeviceEvidence,
		}
		source.Keyserver = client.Fetch
	}
	values, secretDetail, err := prepareSecretHandoff(ctx, workload, source, secretHandoff, options.ConfigHash)
	if err != nil {
		tracker.Record(bootstate.StageKeyserverSecrets, bootstate.StatusFailed, time.Since(start), err.Error())
		return err
	}
	tracker.Record(bootstate.StageKeyserverSecrets, bootstate.StatusOK, time.Since(start), secretDetail)

	if workload.Prepare != nil {
		if err := workload.Prepare(tracker, externalConfig, values.workload); err != nil {
			return err
		}
	}

	// Models
	start = time.Now()
	log.Println("Mounting models")
	if err := modelpack.MountAll(workload.Mounts, values.modelKeys); err != nil {
		tracker.Record("models", bootstate.StatusFailed, time.Since(start), err.Error())
		return fmt.Errorf("model mount failed: %w", err)
	}
	tracker.Record("models", bootstate.StatusOK, time.Since(start), "")

	return nil
}

type resolvedSecrets struct {
	modelKeys secretstore.Store
	workload  secretstore.Store
}

func prepareSecretHandoff(ctx context.Context, workload Workload, source secretstore.Source, handoff *os.File, digest string) (resolvedSecrets, string, error) {
	names := append(modelpack.SecretReferences(workload.Mounts), workload.Secrets...)
	values, detail, err := source.Resolve(ctx, names)
	if err != nil {
		return resolvedSecrets{}, "", err
	}
	selected, err := secretstore.Select(workload.Secrets, values)
	if err != nil {
		return resolvedSecrets{}, "", fmt.Errorf("resolving workload secrets: %w", err)
	}
	keys, err := secretstore.Select(modelpack.SecretReferences(workload.Mounts), values)
	if err != nil {
		return resolvedSecrets{}, "", fmt.Errorf("resolving model keys: %w", err)
	}
	if err := secretstore.WriteHandoff(handoff, digest, selected); err != nil {
		return resolvedSecrets{}, "", fmt.Errorf("creating sealed secret handoff: %w", err)
	}
	return resolvedSecrets{modelKeys: keys, workload: selected}, fmt.Sprintf("handed off %d workload secret(s); %s", len(selected), detail), nil
}
