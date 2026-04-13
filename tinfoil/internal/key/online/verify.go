package online

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"time"
)

const (
	validationTimeout  = 10 * time.Second
	maxErrorBodyBytes  = 1024
)

// AllowedControlPlaneHosts is the set of hostnames the validator will talk to.
// It is a package variable so tests can extend it; production builds should
// treat it as constant.
//
// TODO: replace bare-200 trust with a signed response (Ed25519 over
// {keyHash, exp, enclaveTLSKeyFP}) verified against an image-baked pubkey.
var AllowedControlPlaneHosts = []string{
	"api.tinfoil.sh",
}

type Validator struct {
	server string
	client *http.Client
}

func NewValidator(server string) (*Validator, error) {
	u, err := url.Parse(server)
	if err != nil {
		return nil, fmt.Errorf("invalid validation server URL: %w", err)
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("validation server must use HTTPS: %s", server)
	}
	if !slices.Contains(AllowedControlPlaneHosts, u.Hostname()) {
		return nil, fmt.Errorf("validation server host %q is not in the allowlist", u.Hostname())
	}
	return &Validator{
		server: server,
		client: &http.Client{Timeout: validationTimeout},
	}, nil
}

type ValidationError struct {
	StatusCode int
	Message    string
}

func (e *ValidationError) Error() string {
	return e.Message
}

func (v *Validator) Validate(apiKey string) error {
	hash := sha256.Sum256([]byte(apiKey))
	payload := hex.EncodeToString(hash[:])

	resp, err := v.client.Post(v.server, "text/plain", bytes.NewBufferString(payload))
	if err != nil {
		return fmt.Errorf("validation request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyBytes))
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	return &ValidationError{
		StatusCode: resp.StatusCode,
		Message:    string(body),
	}
}
