package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"slices"
	"strings"

	verifier "github.com/tinfoilsh/tinfoil-go/verifier/attestation"

	"tinfoil/internal/attestation"
	shimconfig "tinfoil/internal/config"
)

type vaultFetchRequest struct {
	Repo       string           `json:"repo"`
	SecretRefs []string         `json:"secret_refs"`
	Bundle     *verifier.Bundle `json:"bundle"`
	Token      string           `json:"token"`
	Nonce      string           `json:"nonce"`
}

// fetchVaultSecrets is the vault boot stage: it asks the confidential secrets
// vault for this workload's secrets and merges them into the external config
// so buildEnv injects them into the container. Only container-declared
// secrets whose values the external config did not populate are requested.
//
// The exchange follows the KBS RCAR shape (request, challenge, attest,
// respond): the vault issues a single-use nonce, the enclave binds it into a
// fresh quote's REPORTDATA, and the vault releases secrets over the TLS
// channel only against that quote — proof the requester is a live measured
// enclave, not a replayed quote and a leaked token.
func fetchVaultSecrets(config *Config, ext *shimconfig.ExternalConfig) error {
	names := missingSecretValues(config, ext)
	if len(names) == 0 {
		log.Println("All declared secrets populated by external config, nothing to fetch")
		return nil
	}
	if ext.VaultToken == "" {
		return fmt.Errorf("%d secret(s) need the vault but external config has no vault-token", len(names))
	}

	nonce, err := vaultChallenge(config.VaultURL)
	if err != nil {
		return fmt.Errorf("fetching vault challenge: %w", err)
	}

	var reportData [64]byte
	copy(reportData[:32], nonce)
	rawReport, platform, err := attestation.Report(reportData)
	if err != nil {
		return fmt.Errorf("fetching quote for vault challenge: %w", err)
	}
	doc, err := attestation.V2Document(rawReport, platform)
	if err != nil {
		return fmt.Errorf("wrapping quote: %w", err)
	}

	req := vaultFetchRequest{
		Repo:       ext.Metadata.Repo,
		SecretRefs: names,
		Bundle: &verifier.Bundle{
			EnclaveAttestationReport: doc,
			Digest:                   ext.Metadata.Digest,
		},
		Token: ext.VaultToken,
		Nonce: hex.EncodeToString(nonce),
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

// vaultChallenge fetches a single-use nonce from the vault to bind into the
// quote's REPORTDATA.
func vaultChallenge(base string) ([]byte, error) {
	url := strings.TrimRight(base, "/") + "/challenge"
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(msg)))
	}
	var challenge struct {
		Nonce string `json:"nonce"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&challenge); err != nil {
		return nil, fmt.Errorf("decoding challenge: %w", err)
	}
	nonce, err := hex.DecodeString(challenge.Nonce)
	if err != nil {
		return nil, fmt.Errorf("decoding nonce: %w", err)
	}
	if len(nonce) != 32 {
		return nil, fmt.Errorf("nonce must be 32 bytes, got %d", len(nonce))
	}
	return nonce, nil
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
