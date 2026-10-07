package ecrregistry

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	SecretName       = "ECR_REGISTRY_AUTH"
	ConfigFileName   = "ecr-refresh.json"
	refreshURL       = "https://api.tinfoil.sh/api/internal/registry/ecr/token"
	refreshTimeout   = 45 * time.Second
	requestTimeout   = 12 * time.Second
	minimumLifetime  = 5 * time.Minute
	maximumAttempts  = 3
	retryInterval    = time.Second
	maxConfigBytes   = 16 * 1024
	maxResponseBytes = 256 * 1024
	maxTokenBytes    = 128
	maxOrgIDBytes    = 128
	registryUsername = "AWS"
)

var hostPattern = regexp.MustCompile(`^[0-9]{12}\.dkr\.ecr\.[a-z]+-(?:[a-z]+-)+[0-9]+\.amazonaws\.com(?:\.cn)?$`)

type Config struct {
	Host  string `json:"host"`
	OrgID string `json:"org_id"`
	Token string `json:"token"`
}

type Credentials struct {
	Host      string    `json:"host"`
	Username  string    `json:"username"`
	Password  string    `json:"password"`
	ExpiresAt time.Time `json:"expires_at"`
}

func decodeConfig(data []byte) (*Config, error) {
	var config Config
	if len(data) > maxConfigBytes || json.Unmarshal(data, &config) != nil || !hostPattern.MatchString(config.Host) ||
		config.OrgID == "" || len(config.OrgID) > maxOrgIDBytes || config.Token == "" || len(config.Token) > maxTokenBytes ||
		strings.ContainsAny(config.Token, "\r\n") {
		return nil, fmt.Errorf("invalid ECR refresh configuration")
	}
	return &config, nil
}

func Configure(path, value string) error {
	if value == "" {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("removing ECR refresh configuration: %w", err)
		}
		return nil
	}
	if _, err := decodeConfig([]byte(value)); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("creating ECR refresh configuration directory: %w", err)
	}
	if err := os.WriteFile(path, []byte(value), 0600); err != nil {
		return fmt.Errorf("writing ECR refresh configuration: %w", err)
	}
	return nil
}

func Load(path string) (*Config, error) {
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("opening ECR refresh configuration: %w", err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxConfigBytes+1))
	if err != nil {
		return nil, fmt.Errorf("reading ECR refresh configuration: %w", err)
	}
	return decodeConfig(data)
}

func (c *Config) Fetch(ctx context.Context, transport http.RoundTripper) (*Credentials, error) {
	ctx, cancel := context.WithTimeout(ctx, refreshTimeout)
	defer cancel()
	client := &http.Client{Transport: transport, Timeout: requestTimeout, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	body, err := json.Marshal(struct {
		OrgID string `json:"org_id"`
		Host  string `json:"host"`
	}{c.OrgID, c.Host})
	if err != nil {
		return nil, fmt.Errorf("encoding ECR refresh request")
	}
	for attempt := 0; attempt < maximumAttempts; attempt++ {
		credentials, retry, err := c.fetchOnce(ctx, client, body)
		if err == nil || !retry || attempt == maximumAttempts-1 {
			return credentials, err
		}
		timer := time.NewTimer(retryInterval << attempt)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
	return nil, fmt.Errorf("ECR registry authentication is unavailable")
}

func (c *Config) fetchOnce(ctx context.Context, client *http.Client, body []byte) (*Credentials, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, refreshURL, bytes.NewReader(body))
	if err != nil {
		return nil, false, fmt.Errorf("creating ECR refresh request")
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, false, ctx.Err()
		}
		return nil, true, fmt.Errorf("ECR registry authentication request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		retry := resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= http.StatusInternalServerError
		return nil, retry, fmt.Errorf("ECR registry authentication failed (HTTP %d)", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, true, fmt.Errorf("reading ECR registry authentication response failed")
	}
	var credentials Credentials
	if len(data) > maxResponseBytes || json.Unmarshal(data, &credentials) != nil || credentials.Host != c.Host ||
		credentials.Username != registryUsername || credentials.Password == "" || !credentials.ExpiresAt.After(time.Now().Add(minimumLifetime)) {
		return nil, false, fmt.Errorf("invalid ECR registry authentication response")
	}
	return &credentials, false, nil
}
