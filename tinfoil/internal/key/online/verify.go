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

func (v *Validator) Validate(req key.Request) (key.Result, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return key.Result{}, fmt.Errorf("marshalling validation request: %w", err)
	}

	resp, err := v.client.Post(v.server, "application/json", bytes.NewReader(body))
	if err != nil {
		return key.Result{}, fmt.Errorf("validation request failed: %w", err)
	}
	defer resp.Body.Close()

	// The control plane knows the subject for opaque keys but does not return
	// it here; the upstream attributes opaque-key usage by the key itself.
	if resp.StatusCode == http.StatusOK {
		return key.Result{}, nil
	}

	return key.Result{}, &key.ValidationError{
		StatusCode: resp.StatusCode,
	}
}
