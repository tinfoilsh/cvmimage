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

const BootPath = "/v1/boot"

type ErrorResponse struct {
	Error string `json:"error"`
}

// Boot starts the runtime from the verified boot config when config is empty.
// A non-empty config is an ephemeral debug override and is independently
// authorized by tinfoil-containers from the kernel command line.
func Boot(ctx context.Context, config []byte) error {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", boot.ContainersSocket)
		},
	}
	defer transport.CloseIdleConnections()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://unix"+BootPath, bytes.NewReader(config))
	if err != nil {
		return err
	}
	if len(config) > 0 {
		request.Header.Set("Content-Type", "application/yaml")
	}
	response, err := (&http.Client{Transport: transport}).Do(request)
	if err != nil {
		return fmt.Errorf("calling tinfoil-containers: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode >= 200 && response.StatusCode < 300 {
		return nil
	}
	data, readErr := io.ReadAll(io.LimitReader(response.Body, 64<<10))
	if readErr != nil {
		return fmt.Errorf("reading tinfoil-containers error response: %w", readErr)
	}
	var failure ErrorResponse
	if json.Unmarshal(data, &failure) == nil && failure.Error != "" {
		return fmt.Errorf("tinfoil-containers: %s", failure.Error)
	}
	return fmt.Errorf("tinfoil-containers returned %s", response.Status)
}
