package attestationmaterial

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	wire "github.com/tinfoilsh/tinfoil-go/verifier/collaterals"
)

const maxResponseSize = 20 << 20

type Client struct {
	endpoint string
	http     *http.Client
}

func NewClient(baseURL string, httpClient *http.Client) (*Client, error) {
	base, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("parsing ATC URL: %w", err)
	}
	if base.Scheme != "http" && base.Scheme != "https" {
		return nil, fmt.Errorf("ATC URL must use http or https")
	}
	if base.Host == "" {
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

func (c *Client) Fetch(ctx context.Context, request wire.Request) (wire.Response, error) {
	body, err := json.Marshal(request)
	if err != nil {
		return wire.Response{}, fmt.Errorf("marshaling collaterals request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return wire.Response{}, fmt.Errorf("building collaterals request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
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

	response, err := ParseResponse(respBody)
	if err != nil {
		return wire.Response{}, err
	}
	if response.ExpiresAt.IsZero() {
		return wire.Response{}, fmt.Errorf("collaterals response is missing expires_at")
	}
	if !time.Now().Before(response.ExpiresAt) {
		return wire.Response{}, fmt.Errorf("collaterals response is already expired at %s", response.ExpiresAt.Format(time.RFC3339))
	}
	return response, nil
}

func ParseResponse(data []byte) (wire.Response, error) {
	var response wire.Response
	if err := json.Unmarshal(data, &response); err != nil {
		return wire.Response{}, fmt.Errorf("parsing collaterals response: %w", err)
	}
	if response.Format != wire.FormatV2 {
		return wire.Response{}, fmt.Errorf("unexpected collaterals format %q", response.Format)
	}
	return response, nil
}
