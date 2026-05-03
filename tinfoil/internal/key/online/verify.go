package online

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"tinfoil/internal/key"
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
}

func (e *ValidationError) Error() string {
	return http.StatusText(e.StatusCode)
}

func (v *Validator) Validate(req key.Request) error {
	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshalling validation request: %w", err)
	}

	resp, err := v.client.Post(v.server, "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("validation request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		return nil
	}

	return &ValidationError{
		StatusCode: resp.StatusCode,
	}
}
