package attestationmaterial

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	sharedconfig "github.com/tinfoilsh/tinfoil-config"
	wire "github.com/tinfoilsh/tinfoil-go/collaterals"
	"github.com/tinfoilsh/tinfoil-go/verify/document/collateral"
	"gopkg.in/yaml.v3"
)

const (
	maxResponseSize       = 20 << 20
	RegistryTokenSecret   = "CONFIG_REGISTRY_TOKEN"
	maxRegistryTokenBytes = 8 << 10
)

type Client struct {
	endpoint      string
	http          *http.Client
	registryToken string
	config        []byte
}

func (c *Client) UseRegistryCredential(token string) error {
	if token == "" {
		return nil
	}
	endpoint, err := url.Parse(c.endpoint)
	if err != nil {
		return err
	}
	if endpoint.User != nil || endpoint.ForceQuery || endpoint.RawQuery != "" || endpoint.Fragment != "" || endpoint.Scheme != "https" {
		return fmt.Errorf("registry credentials require HTTPS without userinfo, query, or fragment")
	}
	if token == "" || len(token) > maxRegistryTokenBytes {
		return fmt.Errorf("invalid registry credential size")
	}
	c.registryToken = token
	return nil
}

func (c *Client) UseConfigFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	// Boot validates the full measured config; this client reads its disclosure policy.
	var config struct {
		Security sharedconfig.SecurityConfig `yaml:"security"`
	}
	if err := yaml.Unmarshal(data, &config); err != nil {
		return err
	}
	c.config = nil
	if config.Security.IncludeConfigInAttestation {
		c.config = data
	}
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
	found := false
	for i := range response.Collateral {
		entry := &response.Collateral[i]
		if entry.ID != collateral.ConfigID {
			continue
		}
		found = true
		if entry.Format != collateral.ConfigEndorsementV2Format {
			continue
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(entry.Data, &fields); err != nil {
			return wire.Response{}, err
		}
		if fields == nil {
			return wire.Response{}, fmt.Errorf("config endorsement must be an object")
		}
		_, attached := fields["config_base64"]
		if len(c.config) == 0 && !attached {
			continue
		}
		delete(fields, "config_base64")
		if len(c.config) != 0 {
			fields["config_base64"], err = json.Marshal(c.config)
			if err != nil {
				return wire.Response{}, err
			}
		}
		entry.Data, err = json.Marshal(fields)
		if err != nil {
			return wire.Response{}, err
		}
	}
	if !found && request.Runtime != "" && len(c.config) != 0 {
		data, err := json.Marshal(map[string][]byte{"config_base64": c.config})
		if err != nil {
			return wire.Response{}, err
		}
		response.Collateral = append(response.Collateral, collateral.Entry{ID: collateral.ConfigID, Role: collateral.RoleReferenceValues, Format: collateral.ConfigV1Format, Data: data})
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
