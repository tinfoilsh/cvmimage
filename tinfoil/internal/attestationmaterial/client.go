package attestationmaterial

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"

	wire "github.com/tinfoilsh/tinfoil-go/collaterals"
)

var privateATCNetwork = netip.MustParsePrefix("100.64.0.0/10")

const (
	maxResponseSize       = 20 << 20
	RegistryTokenSecret   = "CONFIG_REGISTRY_TOKEN"
	RegistryTokenHeader   = "X-Tinfoil-Registry-Token"
	maxRegistryTokenBytes = 8 << 10
)

type Client struct {
	endpoint      string
	http          *http.Client
	mu            sync.Mutex
	registryToken string
	tokenPath     string
}

func (c *Client) UseRegistryCredential(token, path string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if token == "" {
		return nil
	}
	endpoint, err := url.Parse(c.endpoint)
	if err != nil {
		return err
	}
	address, _ := netip.ParseAddr(endpoint.Hostname())
	privateHTTP := endpoint.Scheme == "http" && (endpoint.Hostname() == "localhost" || address.IsLoopback() || address.IsPrivate() || privateATCNetwork.Contains(address))
	if endpoint.User != nil || endpoint.ForceQuery || endpoint.RawQuery != "" || endpoint.Fragment != "" || (endpoint.Scheme != "https" && !privateHTTP) {
		return fmt.Errorf("registry credentials require HTTPS or a private HTTP ATC URL without userinfo, query, or fragment")
	}
	if persisted, err := os.ReadFile(path); err == nil {
		token = string(persisted)
	} else if !os.IsNotExist(err) {
		return err
	}
	if token == "" || len(token) > maxRegistryTokenBytes {
		return fmt.Errorf("invalid registry credential size")
	}
	c.registryToken, c.tokenPath = token, path
	return nil
}

func (c *Client) saveRegistryCredential(token string) error {
	if token == "" || len(token) > maxRegistryTokenBytes {
		return fmt.Errorf("missing or oversized renewed registry credential")
	}
	file, err := os.CreateTemp(filepath.Dir(c.tokenPath), ".registry-token-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if _, err := file.WriteString(token); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(file.Name(), c.tokenPath); err != nil {
		return err
	}
	c.registryToken = token
	return nil
}

func NewClient(baseURL string, httpClient *http.Client) (*Client, error) {
	base, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("parsing ATC URL: %w", err)
	}
	if base.Scheme != "http" && base.Scheme != "https" {
		return nil, fmt.Errorf("ATC URL must use http or https")
	}
	if base.Hostname() == "" {
		return nil, fmt.Errorf("ATC URL is missing a host")
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	return &Client{
		endpoint: base.JoinPath("attestation-collaterals").String(),
		http:     httpClient,
	}, nil
}

func (c *Client) Fetch(ctx context.Context, request Request) (wire.Response, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := request.Validate(); err != nil {
		return wire.Response{}, err
	}
	body, err := json.Marshal(request)
	if err != nil {
		return wire.Response{}, fmt.Errorf("marshaling collaterals request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return wire.Response{}, fmt.Errorf("building collaterals request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.registryToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.registryToken)
	}

	httpClient := *c.http
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := httpClient.Do(req)
	if err != nil {
		return wire.Response{}, fmt.Errorf("POST %s: %w", c.endpoint, err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize+1))
	if err != nil {
		return wire.Response{}, fmt.Errorf("reading collaterals response: %w", err)
	}
	if len(respBody) > maxResponseSize {
		return wire.Response{}, fmt.Errorf("collaterals response exceeds %d bytes", maxResponseSize)
	}
	if resp.StatusCode != http.StatusOK {
		return wire.Response{}, fmt.Errorf("POST %s: %s: %s", c.endpoint, resp.Status, string(respBody))
	}

	response, err := ParseResponse(respBody, wire.FormatV3)
	if err != nil {
		return wire.Response{}, err
	}
	if response.ExpiresAt.IsZero() {
		return wire.Response{}, fmt.Errorf("collaterals response is missing expires_at")
	}
	if !time.Now().Before(response.ExpiresAt) {
		return wire.Response{}, fmt.Errorf("collaterals response is already expired at %s", response.ExpiresAt.Format(time.RFC3339))
	}
	if c.registryToken != "" {
		if err := c.saveRegistryCredential(resp.Header.Get(RegistryTokenHeader)); err != nil {
			return wire.Response{}, err
		}
	}
	return response, nil
}

func ParseResponse(data []byte, expectedFormat string) (wire.Response, error) {
	var response wire.Response
	if err := json.Unmarshal(data, &response); err != nil {
		return wire.Response{}, fmt.Errorf("parsing collaterals response: %w", err)
	}
	if response.Format != expectedFormat {
		return wire.Response{}, fmt.Errorf("unexpected collaterals format %q", response.Format)
	}
	return response, nil
}
