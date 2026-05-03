package online

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"tinfoil/internal/key/keyreq"
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

func (v *Validator) Validate(req keyreq.Request) error {
	return v.post(v.keyServer, req)
}

func (v *Validator) ValidateWithIP(req keyreq.Request) error {
	return v.post(v.keyAndIPServer, req)
}

func (v *Validator) post(server string, req keyreq.Request) error {
	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshalling validation request: %w", err)
	}

	resp, err := v.client.Post(server, "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("validation request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		return nil
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	return &ValidationError{
		StatusCode: resp.StatusCode,
		Message:    string(respBody),
	}
}
