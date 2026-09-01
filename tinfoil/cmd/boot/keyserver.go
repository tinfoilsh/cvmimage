package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	wire "github.com/tinfoilsh/tinfoil-go/verifier/collaterals"
	"github.com/tinfoilsh/tinfoil-go/verifier/envelope"

	"tinfoil/internal/attestation"
	"tinfoil/internal/attestationmaterial"
	"tinfoil/internal/boot"
	shimconfig "tinfoil/internal/config"
	"tinfoil/internal/secretstore"
)

const (
	keyserverFetchTimeout     = 60 * time.Second
	maxKeyserverChallengeBody = 1024
	maxKeyserverResponseBody  = 8 << 20
)

type keyserverChallengeResponse struct {
	Nonce string `json:"nonce"`
}

type keyserverFetchRequest struct {
	Repo       string          `json:"repo"`
	SecretRefs []string        `json:"secret_refs"`
	Nonce      string          `json:"nonce"`
	Document   json.RawMessage `json:"document"`
}

// fetchKeyserverSecrets asks the keyserver for the declared secrets the
// external config did not populate. The keyserver authenticates a fresh v3
// document and binds it to the mTLS certificate before releasing any value.
func fetchKeyserverSecrets(
	ctx context.Context,
	config *Config,
	ext *shimconfig.ExternalConfig,
	nodeID *NodeIdentity,
	collateralRequest wire.Request,
) (int, error) {
	names := secretstore.MissingReferences(config, ext)
	if len(names) == 0 {
		log.Println("All declared secrets populated by external config, nothing to fetch")
		return 0, nil
	}
	if ext == nil || ext.Metadata.Repo == "" {
		return 0, fmt.Errorf("keyserver secret fetch requires repository metadata")
	}
	if nodeID == nil {
		return 0, fmt.Errorf("keyserver secret fetch requires boot identity")
	}
	if _, err := keyserverBaseURL(config.KeyserverURL); err != nil {
		return 0, err
	}

	cert, err := tls.LoadX509KeyPair(boot.TLSCertPath, boot.TLSKeyPath)
	if err != nil {
		return 0, fmt.Errorf("loading enclave TLS certificate: %w", err)
	}

	// Fetch collateral before obtaining the short-lived challenge nonce. The
	// final document carries this untrusted transport for offline verification.
	collateral, err := prefetchKeyserverCollateral(ctx, config, collateralRequest)
	if err != nil {
		return 0, err
	}

	client := keyserverClient(cert)
	nonce, err := keyserverChallenge(ctx, client, config.KeyserverURL)
	if err != nil {
		return 0, fmt.Errorf("requesting keyserver challenge: %w", err)
	}
	var nonce32 [envelope.NonceSize]byte
	copy(nonce32[:], nonce)
	deviceEvidence, err := attestation.CollectDeviceEvidence(nonce32, config.GPUs)
	if err != nil {
		return 0, fmt.Errorf("collecting keyserver device evidence: %w", err)
	}

	identityBody := nodeID.attestationBody()
	document, err := attestation.BuildAttestation(
		identityBody.TLSKeyFP,
		identityBody.HPKEKey,
		nonce,
		deviceEvidence,
		collateral,
	)
	if err != nil {
		return 0, fmt.Errorf("building keyserver attestation: %w", err)
	}
	documentJSON, err := json.Marshal(document)
	if err != nil {
		return 0, fmt.Errorf("marshaling keyserver attestation: %w", err)
	}

	secrets, err := keyserverFetch(ctx, client, config.KeyserverURL, keyserverFetchRequest{
		Repo:       ext.Metadata.Repo,
		SecretRefs: names,
		Nonce:      hex.EncodeToString(nonce),
		Document:   documentJSON,
	})
	if err != nil {
		return 0, err
	}
	if err := mergeKeyserverSecrets(names, secrets, ext); err != nil {
		return 0, err
	}
	log.Printf("Keyserver released %d secret(s) for %s", len(secrets), ext.Metadata.Repo)
	return len(secrets), nil
}

func prefetchKeyserverCollateral(
	ctx context.Context,
	config *Config,
	request wire.Request,
) ([]envelope.CollateralEntry, error) {
	if request.Repo == "" || request.Platform == "" || request.Platform == attestation.PlatformDummy || request.QuoteBase64 == "" {
		return nil, fmt.Errorf("keyserver secret fetch requires raw CPU attestation")
	}
	client, err := attestationmaterial.NewClient(config.ShimCfg.ATC, nil)
	if err != nil {
		return nil, fmt.Errorf("creating ATC client: %w", err)
	}
	response, err := client.Fetch(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("prefetching keyserver collateral: %w", err)
	}
	return response.Collateral, nil
}

func mergeKeyserverSecrets(names []string, secrets map[string]string, ext *shimconfig.ExternalConfig) error {
	if len(secrets) != len(names) {
		return fmt.Errorf("keyserver returned %d secret(s), expected %d", len(secrets), len(names))
	}
	for _, name := range names {
		value, ok := secrets[name]
		if !ok || value == "" || value == "null" {
			return fmt.Errorf("keyserver did not return declared secret %q", name)
		}
	}

	if ext.Secrets == nil {
		ext.Secrets = make(map[string]string, len(secrets))
	}
	for name, value := range secrets {
		ext.Secrets[name] = value
	}
	return nil
}

// keyserverClient presents the enclave certificate and refuses redirects so
// the measured keyserver origin is the only peer that can request that
// credential.
func keyserverClient(cert tls.Certificate) *http.Client {
	return &http.Client{
		Timeout: keyserverFetchTimeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{cert},
				MinVersion:   tls.VersionTLS12,
			},
		},
	}
}

func keyserverChallenge(ctx context.Context, client *http.Client, base string) ([]byte, error) {
	endpoint, err := keyserverEndpoint(base, "challenge")
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var challenge keyserverChallengeResponse
	if err := decodeKeyserverResponse(resp, maxKeyserverChallengeBody, &challenge); err != nil {
		return nil, err
	}
	if challenge.Nonce != strings.ToLower(challenge.Nonce) {
		return nil, fmt.Errorf("keyserver returned a non-canonical nonce")
	}
	nonce, err := hex.DecodeString(challenge.Nonce)
	if err != nil || len(nonce) != envelope.NonceSize {
		return nil, fmt.Errorf("keyserver returned an invalid nonce")
	}
	return nonce, nil
}

func keyserverFetch(ctx context.Context, client *http.Client, base string, request keyserverFetchRequest) (map[string]string, error) {
	body, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	endpoint, err := keyserverEndpoint(base, "fetch")
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var secrets map[string]string
	if err := decodeKeyserverResponse(resp, maxKeyserverResponseBody, &secrets); err != nil {
		return nil, err
	}
	return secrets, nil
}

func keyserverEndpoint(base, path string) (string, error) {
	parsed, err := keyserverBaseURL(base)
	if err != nil {
		return "", err
	}
	return parsed.JoinPath(path).String(), nil
}

func keyserverBaseURL(base string) (*url.URL, error) {
	parsed, err := url.Parse(base)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
		return nil, fmt.Errorf("keyserver-url must be an https URL without userinfo, got %q", base)
	}
	return parsed, nil
}

func decodeKeyserverResponse(response *http.Response, limit int64, target any) error {
	body, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return fmt.Errorf("reading keyserver response: %w", err)
	}
	if int64(len(body)) > limit {
		return fmt.Errorf("keyserver response exceeds %d bytes", limit)
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: %s", response.Status, strings.TrimSpace(string(body)))
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("decoding keyserver response: %w", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("decoding keyserver response: trailing JSON data")
	}
	return nil
}
