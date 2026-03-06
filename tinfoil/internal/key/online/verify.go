package online

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const validationTimeout = 10 * time.Second

type Validator struct {
	server string
	client *http.Client
}

func NewValidator(server string) (*Validator, error) {
	if !strings.HasPrefix(server, "https://") {
		return nil, fmt.Errorf("validation server must use HTTPS: %s", server)
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
	resp, err := v.client.Post(v.server, "application/json", bytes.NewBufferString(apiKey))
	if err != nil {
		return fmt.Errorf("validation request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		return nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	return &ValidationError{
		StatusCode: resp.StatusCode,
		Message:    string(body),
	}
}
