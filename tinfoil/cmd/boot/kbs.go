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
	kbsFetchTimeout     = 60 * time.Second
	maxKBSChallengeBody = 1024
	maxKBSResponseBody  = 8 << 20
)

type kbsChallengeResponse struct {
	Nonce string `json:"nonce"`
}

type kbsFetchRequest struct {
	Repo       string          `json:"repo"`
	SecretRefs []string        `json:"secret_refs"`
	Nonce      string          `json:"nonce"`
	Document   json.RawMessage `json:"document"`
}

// fetchKBSSecrets asks the KBS for the declared secrets the external config
// did not populate. The KBS authenticates a fresh v3 document and binds it to
// the mTLS certificate before releasing any value.
func fetchKBSSecrets(
	ctx context.Context,
	baseURL string,
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
		return 0, fmt.Errorf("KBS secret fetch requires repository metadata")
	}
	if nodeID == nil {
		return 0, fmt.Errorf("KBS secret fetch requires boot identity")
	}
	if _, err := kbsBaseURL(baseURL); err != nil {
		return 0, err
	}

	cert, err := tls.LoadX509KeyPair(boot.TLSCertPath, boot.TLSKeyPath)
	if err != nil {
		return 0, fmt.Errorf("loading enclave TLS certificate: %w", err)
	}

	// Fetch collateral before obtaining the short-lived challenge nonce. The
	// final document carries this untrusted transport for offline verification.
	collateral, err := prefetchKBSCollateral(ctx, config, collateralRequest)
	if err != nil {
		return 0, err
	}

	client := kbsClient(cert)
	nonce, err := kbsChallenge(ctx, client, baseURL)
	if err != nil {
		return 0, fmt.Errorf("requesting KBS challenge: %w", err)
	}
	var nonce32 [envelope.NonceSize]byte
	copy(nonce32[:], nonce)
	deviceEvidence, err := attestation.CollectDeviceEvidence(nonce32, config.GPUs)
	if err != nil {
		return 0, fmt.Errorf("collecting KBS device evidence: %w", err)
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
		return 0, fmt.Errorf("building KBS attestation: %w", err)
	}
	documentJSON, err := json.Marshal(document)
	if err != nil {
		return 0, fmt.Errorf("marshaling KBS attestation: %w", err)
	}

	secrets, err := kbsFetch(ctx, client, baseURL, kbsFetchRequest{
		Repo:       ext.Metadata.Repo,
		SecretRefs: names,
		Nonce:      hex.EncodeToString(nonce),
		Document:   documentJSON,
	})
	if err != nil {
		return 0, err
	}
	if err := mergeKBSSecrets(names, secrets, ext); err != nil {
		return 0, err
	}
	log.Printf("KBS released %d secret(s) for %s", len(secrets), ext.Metadata.Repo)
	return len(secrets), nil
}

func prefetchKBSCollateral(
	ctx context.Context,
	config *Config,
	request wire.Request,
) ([]envelope.CollateralEntry, error) {
	if request.Repo == "" || request.Platform == "" || request.Platform == attestation.PlatformDummy || request.QuoteBase64 == "" {
		return nil, fmt.Errorf("KBS secret fetch requires raw CPU attestation")
	}
	client, err := attestationmaterial.NewClient(config.ShimCfg.ATC, nil)
	if err != nil {
		return nil, fmt.Errorf("creating ATC client: %w", err)
	}
	response, err := client.Fetch(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("prefetching KBS collateral: %w", err)
	}
	return response.Collateral, nil
}

func mergeKBSSecrets(names []string, secrets map[string]string, ext *shimconfig.ExternalConfig) error {
	if len(secrets) != len(names) {
		return fmt.Errorf("KBS returned %d secret(s), expected %d", len(secrets), len(names))
	}
	for _, name := range names {
		value, ok := secrets[name]
		if !ok || value == "" || value == "null" {
			return fmt.Errorf("KBS did not return declared secret %q", name)
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

// kbsClient presents the enclave certificate and refuses redirects so the
// measured KBS origin is the only peer that can request that credential.
func kbsClient(cert tls.Certificate) *http.Client {
	return &http.Client{
		Timeout: kbsFetchTimeout,
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

func kbsChallenge(ctx context.Context, client *http.Client, base string) ([]byte, error) {
	endpoint, err := kbsEndpoint(base, "challenge")
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
	var challenge kbsChallengeResponse
	if err := decodeKBSResponse(resp, maxKBSChallengeBody, &challenge); err != nil {
		return nil, err
	}
	if challenge.Nonce != strings.ToLower(challenge.Nonce) {
		return nil, fmt.Errorf("KBS returned a non-canonical nonce")
	}
	nonce, err := hex.DecodeString(challenge.Nonce)
	if err != nil || len(nonce) != envelope.NonceSize {
		return nil, fmt.Errorf("KBS returned an invalid nonce")
	}
	return nonce, nil
}

func kbsFetch(ctx context.Context, client *http.Client, base string, request kbsFetchRequest) (map[string]string, error) {
	body, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	endpoint, err := kbsEndpoint(base, "fetch")
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
	if err := decodeKBSResponse(resp, maxKBSResponseBody, &secrets); err != nil {
		return nil, err
	}
	return secrets, nil
}

func kbsEndpoint(base, path string) (string, error) {
	parsed, err := kbsBaseURL(base)
	if err != nil {
		return "", err
	}
	return parsed.JoinPath(path).String(), nil
}

func kbsBaseURL(base string) (*url.URL, error) {
	parsed, err := url.Parse(base)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
		return nil, fmt.Errorf("KBS URL must be an https URL without userinfo, got %q", base)
	}
	return parsed, nil
}

func decodeKBSResponse(response *http.Response, limit int64, target any) error {
	body, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return fmt.Errorf("reading KBS response: %w", err)
	}
	if int64(len(body)) > limit {
		return fmt.Errorf("KBS response exceeds %d bytes", limit)
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: %s", response.Status, strings.TrimSpace(string(body)))
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("decoding KBS response: %w", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("decoding KBS response: trailing JSON data")
	}
	return nil
}
