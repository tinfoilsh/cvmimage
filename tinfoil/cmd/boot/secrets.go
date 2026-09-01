package main

import (
	"context"
	"fmt"
	"log"
	"os"

	shimconfig "tinfoil/internal/config"
	"tinfoil/internal/secretstore"
)

// keyserverFetcher releases the named secrets from the customer's keyserver.
type keyserverFetcher func(ctx context.Context, names []string) (map[string]string, error)

// prepareSecretHandoff resolves every declared secret from exactly one
// source. With keyserver-url set that source is the keyserver: a value the
// host supplied for a declared name is refused rather than merged, so the
// host cannot substitute its own. Debug enclaves are the exception; the
// keyserver rejects their attestation, so they take host values instead.
func prepareSecretHandoff(
	ctx context.Context,
	config *Config,
	externalConfig *shimconfig.ExternalConfig,
	handoff *os.File,
	configDigest string,
	debug bool,
	fetch keyserverFetcher,
) (string, error) {
	names := secretstore.AllReferences(config)
	var source string
	switch {
	case config.KeyserverURL == "":
		source = "keyserver not configured"
	case debug:
		log.Println("Debug enclave: keyserver-url ignored, secrets supplied by host")
		source = "debug enclave: keyserver-url ignored, secrets supplied by host"
	default:
		if externalConfig == nil {
			return "", fmt.Errorf("keyserver secret fetch requires external config")
		}
		for _, name := range names {
			if externalConfig.GetSecret(name) != "" {
				return "", fmt.Errorf("host supplied secret %q, but keyserver-url is set and declared secrets must come from the keyserver", name)
			}
		}
		if len(names) != 0 {
			log.Println("Fetching keyserver secrets")
			secrets, err := fetch(ctx, names)
			if err != nil {
				return "", fmt.Errorf("keyserver secret fetch failed: %w", err)
			}
			if err := mergeKeyserverSecrets(names, secrets, externalConfig); err != nil {
				return "", fmt.Errorf("keyserver secret fetch failed: %w", err)
			}
		}
		source = fmt.Sprintf("fetched %d from keyserver", len(names))
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
	return fmt.Sprintf("handed off %d workload secret(s); %s", len(workloadSecrets), source), nil
}
