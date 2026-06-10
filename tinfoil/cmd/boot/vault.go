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

	"github.com/tinfoilsh/encrypted-http-body-protocol/identity"
	verifier "github.com/tinfoilsh/tinfoil-go/verifier/attestation"

	"tinfoil/internal/boot"
	shimconfig "tinfoil/internal/config"
)

// vaultFetchInfo must match the vault's HPKE info string
// (confidential-secrets-vault/fetch.go).
const vaultFetchInfo = "tinfoil-secrets-vault/fetch/v1"

type vaultFetchRequest struct {
	Repo       string           `json:"repo"`
	SecretRefs []string         `json:"secret_refs"`
	Bundle     *verifier.Bundle `json:"bundle"`
	Password   string           `json:"password"`
}

type vaultFetchResponse struct {
	Enc        []byte `json:"enc"`
	Ciphertext []byte `json:"ciphertext"`
}

// fetchVaultSecrets is boot stage 3b: it asks the confidential secrets vault for
// this workload's secrets, decrypts them in-enclave with sk_W, and merges them
// into the (private, host-invisible) external config so buildEnv injects them
// into the containers that declare them. It reuses the per-boot HPKE identity
// and the CPU quote from the preceding stages; the released values never pass
// through the host-authored external config.
//
// The requested secret names are the union of every container's `secrets:`
// list in the measured tinfoil-config.yml — so the request is bound to the
// workload's attested identity, not to a per-deployment file.
func fetchVaultSecrets(cpuAtt *CPUAttestation, config *Config, ext *shimconfig.ExternalConfig) error {
	v := ext.Vault
	id, err := identity.FromFile(boot.HPKEKeyPath)
	if err != nil {
		return fmt.Errorf("loading HPKE identity: %w", err)
	}

	req := vaultFetchRequest{
		Repo:       ext.Repo,
		SecretRefs: declaredSecretNames(config),
		Bundle: &verifier.Bundle{
			EnclaveAttestationReport: cpuAtt.V2Doc,
			Digest:                   v.Digest,
		},
		Password: v.Password,
	}

	resp, err := vaultFetch(v.URL, req)
	if err != nil {
		return err
	}
	plaintext, err := vaultOpen(id, resp.Enc, resp.Ciphertext)
	if err != nil {
		return fmt.Errorf("decrypting release: %w", err)
	}
	var secrets map[string]string
	if err := json.Unmarshal(plaintext, &secrets); err != nil {
		return fmt.Errorf("parsing released secrets: %w", err)
	}

	if ext.Secrets == nil {
		ext.Secrets = make(map[string]string, len(secrets))
	}
	for name, value := range secrets {
		ext.Secrets[name] = value
	}
	log.Printf("Vault released %d secret(s) for %s", len(secrets), ext.Repo)
	return nil
}

// declaredSecretNames returns the deduplicated, sorted union of every
// container's `secrets:` declarations in the measured config.
func declaredSecretNames(config *Config) []string {
	seen := map[string]struct{}{}
	var names []string
	for _, c := range config.Containers {
		for _, n := range c.Secrets {
			if _, ok := seen[n]; ok {
				continue
			}
			seen[n] = struct{}{}
			names = append(names, n)
		}
	}
	slices.Sort(names)
	return names
}

// vaultOpen opens the vault's HPKE-sealed release with sk_W. The identity uses
// circl HPKE; the vault seals with go's crypto/hpke — both are RFC 9180
// X25519/HKDF-SHA256/AES-256-GCM, so they interoperate on the wire.
func vaultOpen(id *identity.Identity, enc, ct []byte) ([]byte, error) {
	receiver, err := id.Suite().NewReceiver(id.PrivateKey(), []byte(vaultFetchInfo))
	if err != nil {
		return nil, fmt.Errorf("hpke receiver: %w", err)
	}
	opener, err := receiver.Setup(enc)
	if err != nil {
		return nil, fmt.Errorf("hpke setup: %w", err)
	}
	return opener.Open(ct, nil)
}

// vaultFetch POSTs to /fetch and decodes the sealed response. Fails fast.
func vaultFetch(base string, req vaultFetchRequest) (*vaultFetchResponse, error) {
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
	var fr vaultFetchResponse
	if err := json.NewDecoder(resp.Body).Decode(&fr); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}
	return &fr, nil
}
