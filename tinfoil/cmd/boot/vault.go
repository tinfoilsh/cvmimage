package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"slices"
	"strings"

	verifier "github.com/tinfoilsh/tinfoil-go/verifier/attestation"

	shimconfig "tinfoil/internal/config"
)

type vaultFetchRequest struct {
	Repo       string           `json:"repo"`
	SecretRefs []string         `json:"secret_refs"`
	Bundle     *verifier.Bundle `json:"bundle"`
	Token      string           `json:"token"`
}

// fetchVaultSecrets is the vault boot stage: it asks the confidential secrets
// vault for this workload's secrets and merges them into the external config
// so buildEnv injects them into the container. The vault verifies the CPU
// quote from the preceding stages and releases secrets over the TLS channel.
// Only container-declared secrets whose values the external config did not
// populate are requested.
func fetchVaultSecrets(cpuAtt *CPUAttestation, config *Config, ext *shimconfig.ExternalConfig) error {
	names := missingSecretValues(config, ext)
	if len(names) == 0 {
		log.Println("All declared secrets populated by external config, nothing to fetch")
		return nil
	}

	req := vaultFetchRequest{
		Repo:       ext.Metadata.Repo,
		SecretRefs: names,
		Bundle: &verifier.Bundle{
			EnclaveAttestationReport: cpuAtt.V2Doc,
			Digest:                   ext.Metadata.Digest,
		},
		Token: ext.VaultToken,
	}

	secrets, err := vaultFetch(config.VaultURL, req)
	if err != nil {
		return err
	}

	if ext.Secrets == nil {
		ext.Secrets = make(map[string]string, len(secrets))
	}
	for name, value := range secrets {
		ext.Secrets[name] = value
	}
	log.Printf("Vault released %d secret(s) for %s", len(secrets), ext.Metadata.Repo)
	return nil
}

// missingSecretValues returns the deduplicated, sorted names of the
// containers' secrets whose values the external config did not populate
func missingSecretValues(config *Config, ext *shimconfig.ExternalConfig) []string {
	seen := map[string]struct{}{}
	var names []string
	for _, c := range config.Containers {
		for _, n := range c.Secrets {
			if _, ok := seen[n]; ok {
				continue
			}
			seen[n] = struct{}{}
			if ext.GetSecret(n) != "" {
				continue
			}
			names = append(names, n)
		}
	}
	slices.Sort(names)
	return names
}

// vaultFetch POSTs to /fetch and decodes the released secrets. Fails fast.
func vaultFetch(base string, req vaultFetchRequest) (map[string]string, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	url := strings.TrimRight(base, "/") + "/fetch"
	resp, err := http.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(msg)))
	}
	var secrets map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&secrets); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}
	return secrets, nil
}
