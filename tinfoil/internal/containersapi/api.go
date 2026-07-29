package containersapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"

	"tinfoil/internal/boot"
)

const ApplyPath = "/v1/apply"

type ApplyRequest struct {
	Config         json.RawMessage `json:"config"`
	ExternalConfig json.RawMessage `json:"external_config"`
	Debug          bool            `json:"debug"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}

func NewApplyRequest(config, externalConfig any, debug bool) (ApplyRequest, error) {
	configJSON, err := json.Marshal(config)
	if err != nil {
		return ApplyRequest{}, fmt.Errorf("marshaling config: %w", err)
	}
	externalJSON, err := json.Marshal(externalConfig)
	if err != nil {
		return ApplyRequest{}, fmt.Errorf("marshaling external config: %w", err)
	}
	return ApplyRequest{Config: configJSON, ExternalConfig: externalJSON, Debug: debug}, nil
}

func Apply(ctx context.Context, request ApplyRequest) error {
	body, err := json.Marshal(request)
	if err != nil {
		return err
	}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", boot.ContainersSocket)
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://unix"+ApplyPath, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("calling tinfoil-containers: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	data, readErr := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if readErr != nil {
		return fmt.Errorf("reading tinfoil-containers error response: %w", readErr)
	}
	var failure ErrorResponse
	if json.Unmarshal(data, &failure) == nil && failure.Error != "" {
		return fmt.Errorf("tinfoil-containers: %s", failure.Error)
	}
	return fmt.Errorf("tinfoil-containers returned %s", resp.Status)
}
