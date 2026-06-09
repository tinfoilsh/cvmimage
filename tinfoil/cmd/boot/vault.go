package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

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
	Nonce      string           `json:"nonce"`
	Bundle     *verifier.Bundle `json:"bundle,omitempty"` // real mode: quote + provenance
	PKW        string           `json:"pk_w,omitempty"`   // dev mode only (claimed key, no quote)
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
func fetchVaultSecrets(nodeID *NodeIdentity, cpuAtt *CPUAttestation, ext *shimconfig.ExternalConfig) error {
	v := ext.Vault
	id, err := identity.FromFile(boot.HPKEKeyPath)
	if err != nil {
		return fmt.Errorf("loading HPKE identity: %w", err)
	}

	req := vaultFetchRequest{
		Repo:       v.Repo,
		SecretRefs: v.Secrets,
		Nonce:      strconv.FormatInt(time.Now().UnixNano(), 10),
	}
	if v.Dev {
		log.Println("WARNING: vault dev mode — sending claimed pk_w without attestation")
		req.PKW = hex.EncodeToString(nodeID.HPKEKeyBytes)
	} else {
		req.Bundle = &verifier.Bundle{
			EnclaveAttestationReport: cpuAtt.V2Doc,
			Digest:                   v.Digest,
		}
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
	log.Printf("Vault released %d secret(s) for %s", len(secrets), v.Repo)
	return nil
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

// vaultFetch POSTs to the vault's /fetch with bounded retry — the release is a
// hard boot dependency, so we fail the boot rather than launch a secret-less
// container.
func vaultFetch(base string, req vaultFetchRequest) (*vaultFetchResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	url := strings.TrimRight(base, "/") + "/fetch"
	var lastErr error
	for attempt := 1; attempt <= 6; attempt++ {
		fr, err := vaultTryFetch(url, body)
		if err == nil {
			return fr, nil
		}
		lastErr = err
		log.Printf("vault /fetch attempt %d/6 failed: %v", attempt, err)
		time.Sleep(10 * time.Second)
	}
	return nil, fmt.Errorf("vault fetch failed after retries: %w", lastErr)
}

func vaultTryFetch(url string, body []byte) (*vaultFetchResponse, error) {
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
