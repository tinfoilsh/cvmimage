package online

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"

	"tinfoil/internal/key"
)

const (
	validationTimeout           = 10 * time.Second
	validationCacheTTLHeader    = "X-Tinfoil-Auth-Cache-Ttl-Ms"
	maxValidationCacheTTL       = 30 * time.Second
	maxValidationCacheEntries   = 10000
	metricsValidationPath       = "/metrics"
	maxValidationErrorBodyBytes = 64 << 10
	// maxRefusalMessageBytes bounds the message relayed to the client.
	maxRefusalMessageBytes = 1 << 10
	// unknownStatusMessage describes a refusal whose status has no standard
	// text and whose body carries no OpenAI-style error.
	unknownStatusMessage = "API key validation failed."
)

type Validator struct {
	server string
	client *http.Client
	cache  *lru.Cache[[sha256.Size]byte, time.Time]
	now    func() time.Time
}

func NewValidator(server string) (*Validator, error) {
	if !strings.HasPrefix(server, "https://") {
		return nil, fmt.Errorf("validation server must use HTTPS: %s", server)
	}
	cache, err := lru.New[[sha256.Size]byte, time.Time](maxValidationCacheEntries)
	if err != nil {
		return nil, err
	}
	return &Validator{
		server: server,
		cache:  cache,
		now:    time.Now,
		client: &http.Client{Timeout: validationTimeout},
	}, nil
}

func (v *Validator) Validate(req key.Request) error {
	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshalling validation request: %w", err)
	}

	cacheKey := sha256.Sum256(body)
	if req.Path != metricsValidationPath {
		if deadline, ok := v.cache.Get(cacheKey); ok && v.now().Before(deadline) {
			return nil
		}
	}
	started := v.now()
	resp, err := v.client.Post(v.server, "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("validation request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		if req.Path != metricsValidationPath {
			if ttl := validationCacheTTL(resp.Header); ttl > 0 {
				// Transit time consumes validity; cache hits never extend it.
				deadline := started.Add(ttl)
				if v.now().Before(deadline) {
					v.cache.Add(cacheKey, deadline)
				}
			}
		}
		return nil
	}

	refusal := refusalFromBody(resp.StatusCode, resp.Body)
	refusal.RetryAfter = retryAfter(resp.Header)
	return refusal
}

func validationCacheTTL(header http.Header) time.Duration {
	values := header.Values(validationCacheTTLHeader)
	if len(values) != 1 {
		return 0
	}
	milliseconds, err := strconv.ParseInt(values[0], 10, 64)
	if err != nil || milliseconds <= 0 || milliseconds > maxValidationCacheTTL.Milliseconds() {
		return 0
	}
	return time.Duration(milliseconds) * time.Millisecond
}

// refusalFromBody relays the control plane's OpenAI-style error, which is
// written for the client and names why the credential was refused. Any other
// body, such as an intermediary's error page, may hold private detail, so the
// client gets only the status text and the error type the status implies.
func refusalFromBody(status int, body io.Reader) *key.ValidationError {
	data, err := io.ReadAll(io.LimitReader(body, maxValidationErrorBodyBytes+1))
	var payload struct {
		Error struct {
			Type    string `json:"type"`
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err == nil && len(data) <= maxValidationErrorBodyBytes && json.Unmarshal(data, &payload) == nil &&
		payload.Error.Type != "" && payload.Error.Message != "" && len(payload.Error.Message) <= maxRefusalMessageBytes {
		return &key.ValidationError{
			StatusCode: status,
			Type:       payload.Error.Type,
			Code:       payload.Error.Code,
			Message:    payload.Error.Message,
		}
	}
	message := http.StatusText(status)
	if message == "" {
		message = unknownStatusMessage
	}
	return &key.ValidationError{StatusCode: status, Type: errorTypeForStatus(status), Message: message}
}

func errorTypeForStatus(status int) string {
	switch {
	case status == http.StatusPaymentRequired:
		return key.ErrTypeInsufficientQuota
	case status == http.StatusTooManyRequests:
		return key.ErrTypeRateLimit
	case status == http.StatusServiceUnavailable:
		return key.ErrTypeServiceUnavailable
	case status >= http.StatusInternalServerError:
		return key.ErrTypeServer
	default:
		return key.ErrTypeInvalidRequest
	}
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
