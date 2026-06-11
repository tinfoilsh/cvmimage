package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	verifier "github.com/tinfoilsh/tinfoil-go/verifier/attestation"

	"tinfoil/internal/boot"
	shimconfig "tinfoil/internal/config"
)

type vaultFetchRequest struct {
	Repo       string           `json:"repo"`
	SecretRefs []string         `json:"secret_refs"`
	Bundle     *verifier.Bundle `json:"bundle"`
	Token      string           `json:"token"`
}

// fetchVaultSecrets asks the vault for the declared secrets the external
// config did not populate. The requester is authenticated by mutual TLS
// pinned to the attestation: the request carries the boot attestation
// document, whose REPORTDATA binds the enclave's TLS public key, and the
// connection presents a client certificate over that same key. The handshake
// proves live possession of the key, so the (public) document and a leaked
// token are not enough — only the measured enclave holding the key can fetch.
func fetchVaultSecrets(config *Config, ext *shimconfig.ExternalConfig, tlsKey *ecdsa.PrivateKey, attDoc *verifier.Document) error {
	names := missingSecretValues(config, ext)
	if len(names) == 0 {
		log.Println("All declared secrets populated by external config, nothing to fetch")
		return nil
	}
	if ext.VaultToken == "" {
		return fmt.Errorf("%d secret(s) need the vault but external config has no vault-token", len(names))
	}

	client, err := vaultClient(tlsKey)
	if err != nil {
		return fmt.Errorf("building vault client: %w", err)
	}

	req := vaultFetchRequest{
		Repo:       ext.Metadata.Repo,
		SecretRefs: names,
		Bundle: &verifier.Bundle{
			EnclaveAttestationReport: attDoc,
			Digest:                   ext.Metadata.Digest,
		},
		Token: ext.VaultToken,
	}

	secrets, err := vaultFetch(client, config.VaultURL, req)
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

// vaultClient returns an HTTP client presenting a client certificate over the
// enclave's attested TLS key. The certificate wrapper carries no trust of its
// own — the vault pins the key fingerprint against the attested REPORTDATA —
// so a fresh self-signed one is enough.
func vaultClient(tlsKey *ecdsa.PrivateKey) (*http.Client, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generating serial number: %w", err)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "tinfoil-enclave"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &tlsKey.PublicKey, tlsKey)
	if err != nil {
		return nil, fmt.Errorf("creating client certificate: %w", err)
	}
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: tlsKey}},
				MinVersion:   tls.VersionTLS12,
			},
		},
	}, nil
}

// loadVaultIdentity reads the TLS key and boot attestation document persisted
// by boot, for vault fetches re-run after boot (the boot path passes both
// from memory).
func loadVaultIdentity() (*ecdsa.PrivateKey, *verifier.Document, error) {
	keyPEM, err := os.ReadFile(boot.TLSKeyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("reading TLS key: %w", err)
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, nil, fmt.Errorf("no PEM block in %s", boot.TLSKeyPath)
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing TLS key: %w", err)
	}

	data, err := os.ReadFile(boot.AttestationPath)
	if err != nil {
		return nil, nil, fmt.Errorf("reading attestation document: %w", err)
	}
	var doc verifier.Document
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, nil, fmt.Errorf("parsing attestation document: %w", err)
	}
	return key, &doc, nil
}

// vaultFetch POSTs to /fetch and decodes the released secrets. Fails fast.
func vaultFetch(client *http.Client, base string, req vaultFetchRequest) (map[string]string, error) {
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
