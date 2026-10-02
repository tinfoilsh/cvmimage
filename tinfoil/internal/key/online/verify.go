package online

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"tinfoil/internal/key"
)

const (
	validationTimeout           = 10 * time.Second
	maxValidationErrorBodyBytes = 64 << 10
	insufficientQuota           = "insufficient_quota"
)

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

	validationErr := &key.ValidationError{
		StatusCode: resp.StatusCode,
		RetryAfter: retryAfter(resp.Header),
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxValidationErrorBodyBytes+1))
		var payload struct {
			Error struct {
				Type string `json:"type"`
				Code string `json:"code"`
			} `json:"error"`
		}
		if err == nil && len(body) <= maxValidationErrorBodyBytes && json.Unmarshal(body, &payload) == nil {
			validationErr.QuotaExceeded = payload.Error.Code == insufficientQuota || payload.Error.Type == insufficientQuota
		}
	}
	return validationErr
}

func retryAfter(header http.Header) string {
	values := header.Values("Retry-After")
	if len(values) != 1 {
		return ""
	}
	value := strings.TrimSpace(values[0])
	if _, err := strconv.ParseUint(value, 10, 64); err == nil {
		return value
	}
	if _, err := http.ParseTime(value); err == nil {
		return value
	}
	return ""
}
