package online

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"

	"tinfoil/internal/key"
)

const (
	validationTimeout           = 10 * time.Second
	validationCacheExpiryHeader = "X-Tinfoil-Auth-Cache-Expiry"
	validationCacheNoExpiry     = "none"
	maxBackgroundValidations    = 128
	expiredValidationCode       = "invalid_api_key"
	maxValidationCacheEntries   = 10000
	metricsValidationPath       = "/metrics"
	maxValidationErrorBodyBytes = 64 << 10
	// maxRefusalMessageBytes bounds the message relayed to the client.
	maxRefusalMessageBytes = 1 << 10
	// unknownStatusMessage describes a refusal whose status has no standard
	// text and whose body carries no OpenAI-style error.
	unknownStatusMessage = "API key validation failed."
)

type validationFlight struct {
	active     int
	generation uint64
}

type cachePermission struct {
	expiry    time.Time
	cacheable bool
}

type Validator struct {
	server     string
	client     *http.Client
	cache      *lru.Cache[[sha256.Size]byte, time.Time]
	now        func() time.Time
	mu         sync.Mutex
	flights    map[[sha256.Size]byte]*validationFlight
	background chan struct{}
	refreshes  sync.WaitGroup
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
		server:     server,
		cache:      cache,
		now:        time.Now,
		client:     &http.Client{Timeout: validationTimeout},
		flights:    make(map[[sha256.Size]byte]*validationFlight),
		background: make(chan struct{}, maxBackgroundValidations),
	}, nil
}

func (v *Validator) Validate(req key.Request) error {
	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshalling validation request: %w", err)
	}
	if req.Path == metricsValidationPath {
		_, err := v.validateOnline(body, false)
		return err
	}

	cacheKey := sha256.Sum256(body)
	v.mu.Lock()
	expiry, allowed := v.cache.Get(cacheKey)
	if allowed && !expiry.IsZero() && !v.now().Before(expiry) {
		v.cache.Remove(cacheKey)
		allowed = false
	}
	if allowed {
		if v.flights[cacheKey] != nil {
			v.mu.Unlock()
			return nil
		}
		select {
		case v.background <- struct{}{}:
			flight, generation := v.beginValidationLocked(cacheKey)
			v.refreshes.Add(1)
			v.mu.Unlock()
			go func() {
				defer v.refreshes.Done()
				defer func() { <-v.background }()
				permission, err := v.validateOnline(body, true)
				v.finishValidation(cacheKey, flight, generation, permission, err)
				if err != nil {
					log.Print("Warning: asynchronous API key validation failed; cached allowance removed")
				}
			}()
			return nil
		default:
		}
	}
	flight, generation := v.beginValidationLocked(cacheKey)
	v.mu.Unlock()
	permission, err := v.validateOnline(body, true)
	v.finishValidation(cacheKey, flight, generation, permission, err)
	return err
}

func (v *Validator) beginValidationLocked(cacheKey [sha256.Size]byte) (*validationFlight, uint64) {
	flight := v.flights[cacheKey]
	if flight == nil {
		flight = &validationFlight{}
		v.flights[cacheKey] = flight
	}
	flight.active++
	return flight, flight.generation
}

func (v *Validator) finishValidation(cacheKey [sha256.Size]byte, flight *validationFlight, generation uint64, permission cachePermission, err error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if err != nil || !permission.cacheable {
		v.cache.Remove(cacheKey)
		// A late success cannot restore an allowance invalidated by an overlapping check.
		flight.generation++
	} else if generation == flight.generation {
		expiry := permission.expiry
		if current, ok := v.cache.Peek(cacheKey); ok && !current.IsZero() && (expiry.IsZero() || current.Before(expiry)) {
			expiry = current
		}
		if expiry.IsZero() || v.now().Before(expiry) {
			v.cache.Add(cacheKey, expiry)
		} else {
			v.cache.Remove(cacheKey)
		}
	}
	flight.active--
	if flight.active == 0 {
		delete(v.flights, cacheKey)
	}
}

func (v *Validator) validateOnline(body []byte, readPermission bool) (cachePermission, error) {
	resp, err := v.client.Post(v.server, "application/json", bytes.NewReader(body))
	if err != nil {
		return cachePermission{}, fmt.Errorf("validation request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		if !readPermission {
			return cachePermission{}, nil
		}
		permission := validationCachePermission(resp.Header)
		if permission.cacheable && !permission.expiry.IsZero() && !v.now().Before(permission.expiry) {
			return cachePermission{}, &key.ValidationError{StatusCode: http.StatusUnauthorized, Type: key.ErrTypeInvalidRequest, Code: expiredValidationCode, Message: "API key has expired."}
		}
		return permission, nil
	}
	refusal := refusalFromBody(resp.StatusCode, resp.Body)
	refusal.RetryAfter = retryAfter(resp.Header)
	return cachePermission{}, refusal
}

func validationCachePermission(header http.Header) cachePermission {
	values := header.Values(validationCacheExpiryHeader)
	if len(values) != 1 {
		return cachePermission{}
	}
	if values[0] == validationCacheNoExpiry {
		return cachePermission{cacheable: true}
	}
	expiry, err := time.Parse(time.RFC3339Nano, values[0])
	if err != nil || expiry.IsZero() {
		return cachePermission{}
	}
	return cachePermission{expiry: expiry, cacheable: true}
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
