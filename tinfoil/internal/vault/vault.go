// Package vault fetches declared container secrets from the customer's
// attested-release vault. It runs in tinfoil-containers so released values
// reach container environments without ever being persisted to disk.
package vault

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	verifier "tinfoil/internal/legacy"

	"tinfoil/internal/boot"
	shimconfig "tinfoil/internal/config"
	"tinfoil/internal/runtimeconfig"
)

const fetchTimeout = 60 * time.Second

type fetchRequest struct {
	Repo       string           `json:"repo"`
	SecretRefs []string         `json:"secret_refs"`
	Bundle     *verifier.Bundle `json:"bundle"`
	Token      string           `json:"token"`
}

// FetchSecrets asks the vault for the declared secrets the external config
// did not populate, merging released values into ext.
func FetchSecrets(config *runtimeconfig.Config, ext *shimconfig.ExternalConfig) error {
	names := missingSecretValues(config, ext)
	if len(names) == 0 {
		log.Println("All declared secrets populated by external config, nothing to fetch")
		return nil
	}
	if ext.VaultToken == "" {
		return fmt.Errorf("%d secret(s) need the vault but external config has no vault-token", len(names))
	}
	// TLS required
	if u, err := url.Parse(config.VaultURL); err != nil || u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("vault-url must be an https URL, got %q", config.VaultURL)
	}

	cert, err := tls.LoadX509KeyPair(boot.TLSCertPath, boot.TLSKeyPath)
	if err != nil {
		return fmt.Errorf("loading enclave TLS certificate: %w", err)
	}
	attDoc, err := verifier.FromFile(boot.AttestationPath)
	if err != nil {
		return fmt.Errorf("loading boot attestation document: %w", err)
	}

	req := fetchRequest{
		Repo:       ext.Metadata.Repo,
		SecretRefs: names,
		Bundle: &verifier.Bundle{
			EnclaveAttestationReport: attDoc,
			Digest:                   ext.Metadata.Digest,
		},
		Token: ext.VaultToken,
	}

	secrets, err := fetch(client(cert), config.VaultURL, req)
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
func missingSecretValues(config *runtimeconfig.Config, ext *shimconfig.ExternalConfig) []string {
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

// client returns an HTTP client that presents the enclave's TLS certificate
// for mutual TLS. The vault authenticates the connection by pinning the
// certificate's key fingerprint to the attested REPORTDATA, so no separate
// client credential is needed. The vault's own server certificate is verified
// against the system roots (its host is fixed in the measured config).
func client(cert tls.Certificate) *http.Client {
	return &http.Client{
		Timeout: fetchTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{cert},
				MinVersion:   tls.VersionTLS12,
			},
		},
	}
}

// fetch POSTs to /fetch and decodes the released secrets. Fails fast.
func fetch(client *http.Client, base string, req fetchRequest) (map[string]string, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	url := strings.TrimRight(base, "/") + "/fetch"
	resp, err := client.Post(url, "application/json", bytes.NewReader(body))
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
