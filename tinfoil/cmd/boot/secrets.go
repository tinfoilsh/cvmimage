package main

import (
	"context"
	"fmt"
	"log"
	"os"

	wire "github.com/tinfoilsh/tinfoil-go/verifier/collaterals"

	shimconfig "tinfoil/internal/config"
	"tinfoil/internal/secretstore"
)

func prepareSecretHandoff(
	ctx context.Context,
	config *Config,
	externalConfig *shimconfig.ExternalConfig,
	handoff *os.File,
	configDigest string,
	nodeID *NodeIdentity,
	collateralRequest wire.Request,
) (string, error) {
	fetched := 0
	if config.VaultURL != "" {
		log.Println("Fetching vault secrets")
		var err error
		fetched, err = fetchVaultSecrets(ctx, config, externalConfig, nodeID, collateralRequest)
		if err != nil {
			return "", fmt.Errorf("vault secret fetch failed: %w", err)
		}
	}

	if missing := secretstore.MissingReferences(config, externalConfig); len(missing) != 0 {
		return "", fmt.Errorf("%d declared secret(s) remain unresolved", len(missing))
	}
	workloadSecrets, err := secretstore.WorkloadStore(config, externalConfig)
	if err != nil {
		return "", fmt.Errorf("resolving workload secrets: %w", err)
	}
	if err := secretstore.WriteHandoff(handoff, configDigest, workloadSecrets); err != nil {
		return "", fmt.Errorf("creating sealed secret handoff: %w", err)
	}

	detail := fmt.Sprintf("handed off %d workload secret(s)", len(workloadSecrets))
	if fetched != 0 {
		return fmt.Sprintf("%s; fetched %d from vault", detail, fetched), nil
	}
	if config.VaultURL != "" {
		return detail + "; all declared secrets already populated", nil
	}
	return detail + "; vault not configured", nil
}
