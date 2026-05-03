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
	keyServer      string
	keyAndIPServer string
	client         *http.Client
}

func NewValidator(keyServer, keyAndIPServer string) (*Validator, error) {
	if !strings.HasPrefix(keyServer, "https://") {
		return nil, fmt.Errorf("validation server must use HTTPS: %s", keyServer)
	}
	if !strings.HasPrefix(keyAndIPServer, "https://") {
		return nil, fmt.Errorf("validation server must use HTTPS: %s", keyAndIPServer)
	}
	return &Validator{
		keyServer:      keyServer,
		keyAndIPServer: keyAndIPServer,
		client:         &http.Client{Timeout: validationTimeout},
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
	return v.post(v.keyServer, apiKey)
}

func (v *Validator) ValidateWithIP(apiKey string) error {
	return v.post(v.keyAndIPServer, apiKey)
}

func (v *Validator) post(server, apiKey string) error {
	resp, err := v.client.Post(server, "application/json", bytes.NewBufferString(apiKey))
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
