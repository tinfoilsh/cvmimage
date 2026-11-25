package online

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"

	"tinfoil/internal/key"
)

func TestVerifyOnline(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	var lastReq key.Request
	httpmock.RegisterResponder("POST", "https://localhost:8080/validate",
		func(req *http.Request) (*http.Response, error) {
			body, err := io.ReadAll(req.Body)
			if err != nil {
				return httpmock.NewStringResponse(http.StatusInternalServerError, "Internal server error"), nil
			}

			var parsed key.Request
			if err := json.Unmarshal(body, &parsed); err != nil {
				return httpmock.NewStringResponse(http.StatusBadRequest, "bad json"), nil
			}
			lastReq = parsed

			if parsed.APIKey == "good-key" {
				return httpmock.NewStringResponse(http.StatusOK, "OK"), nil
			}

			return httpmock.NewStringResponse(http.StatusUnauthorized, "Unauthorized"), nil
		})

	v, err := NewValidator("https://localhost:8080/validate")
	assert.Nil(t, err)

	assert.Nil(t, v.Validate(key.Request{
		APIKey:        "good-key",
		Domain:        "model.example.com",
		RequestedHost: "realtime-model.model.example.com",
		Path:          "/v1/chat/completions",
	}))
	assert.Equal(t, "model.example.com", lastReq.Domain)
	assert.Equal(t, "realtime-model.model.example.com", lastReq.RequestedHost)
	assert.Equal(t, "/v1/chat/completions", lastReq.Path)

	assert.NotNil(t, v.Validate(key.Request{APIKey: "bad-key"}))
}

func TestRejectHTTP(t *testing.T) {
	_, err := NewValidator("http://localhost:8080/validate")
	assert.NotNil(t, err)
}

func TestValidationErrorHidesInternalDetails(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	httpmock.RegisterResponder("POST", "https://localhost:8080/validate",
		httpmock.NewStringResponder(http.StatusUnauthorized, "internal validator details"))

	v, err := NewValidator("https://localhost:8080/validate")
	assert.Nil(t, err)

	err = v.Validate(key.Request{APIKey: "bad-key"})
	if assert.NotNil(t, err) {
		validationErr, ok := err.(*key.ValidationError)
		if assert.True(t, ok) {
			assert.Equal(t, http.StatusUnauthorized, validationErr.StatusCode)
			assert.NotContains(t, validationErr.Error(), "internal validator details")
			assert.Equal(t, "Unauthorized", validationErr.Message)
		}
	}
}

func TestValidationRelaysOpenAIErrors(t *testing.T) {
	const message = "API access is paused because the account is out of credits."
	const refusal = `{"error":{"type":"insufficient_quota","code":"insufficient_quota","message":"` + message + `"}}`
	relayed := key.ValidationError{StatusCode: http.StatusPaymentRequired, Type: "insufficient_quota", Code: "insufficient_quota", Message: message}
	statusOnly := key.ValidationError{StatusCode: http.StatusPaymentRequired, Type: key.ErrTypeInsufficientQuota, Message: "Payment Required"}
	for _, tc := range []struct {
		name string
		body string
		want key.ValidationError
	}{
		{"openai error", refusal, relayed},
		{"without code", `{"error":{"type":"insufficient_quota","message":"` + message + `"}}`, key.ValidationError{StatusCode: http.StatusPaymentRequired, Type: "insufficient_quota", Message: message}},
		{"at body limit", refusal + strings.Repeat(" ", maxValidationErrorBodyBytes-len(refusal)), relayed},
		{"over body limit", refusal + strings.Repeat(" ", maxValidationErrorBodyBytes), statusOnly},
		{"message over limit", `{"error":{"type":"insufficient_quota","message":"` + strings.Repeat("x", maxRefusalMessageBytes+1) + `"}}`, statusOnly},
		{"without message", `{"error":{"type":"insufficient_quota","code":"insufficient_quota"}}`, statusOnly},
		{"without type", `{"error":{"code":"insufficient_quota","message":"` + message + `"}}`, statusOnly},
		{"plain text", "private control-plane detail", statusOnly},
		{"error string", `{"error":"private control-plane detail"}`, statusOnly},
		{"malformed", `{"error":`, statusOnly},
		{"trailing JSON", refusal + `{}`, statusOnly},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusPaymentRequired)
				io.WriteString(w, tc.body)
			}))
			defer server.Close()
			v := &Validator{server: server.URL, client: server.Client()}
			var validationErr *key.ValidationError
			if err := v.Validate(key.Request{APIKey: "test-key"}); !errors.As(err, &validationErr) {
				t.Fatalf("expected validation error, got %v", err)
			}
			assert.Equal(t, tc.want, *validationErr)
		})
	}
}

func TestValidationTypesUnreadableRefusalsByStatus(t *testing.T) {
	for _, tc := range []struct {
		status  int
		errType string
		message string
	}{
		{http.StatusUnauthorized, key.ErrTypeInvalidRequest, "Unauthorized"},
		{http.StatusTooManyRequests, key.ErrTypeRateLimit, "Too Many Requests"},
		{http.StatusServiceUnavailable, key.ErrTypeServiceUnavailable, "Service Unavailable"},
		{http.StatusBadGateway, key.ErrTypeServer, "Bad Gateway"},
		{520, key.ErrTypeServer, unknownStatusMessage},
	} {
		t.Run(strconv.Itoa(tc.status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				io.WriteString(w, "<html>proxy error page</html>")
			}))
			defer server.Close()
			v := &Validator{server: server.URL, client: server.Client()}
			var validationErr *key.ValidationError
			if err := v.Validate(key.Request{APIKey: "test-key"}); !errors.As(err, &validationErr) {
				t.Fatalf("expected validation error, got %v", err)
			}
			assert.Equal(t, key.ValidationError{StatusCode: tc.status, Type: tc.errType, Message: tc.message}, *validationErr)
		})
	}
}

func TestRetryAfter(t *testing.T) {
	const date = "Wed, 21 Oct 2037 07:28:00 GMT"
	for _, tc := range []struct {
		values []string
		want   string
	}{
		{nil, ""}, {[]string{""}, ""}, {[]string{"0"}, "0"},
		{[]string{" 42 "}, "42"}, {[]string{date}, date},
		{[]string{"-1"}, ""}, {[]string{"+1"}, ""}, {[]string{"1.5"}, ""},
		{[]string{"tomorrow"}, ""}, {[]string{"10", "20"}, ""},
		{[]string{"10, 20"}, ""}, {[]string{"30\r\nX-Injected: yes"}, ""},
	} {
		if got := retryAfter(http.Header{"Retry-After": tc.values}); got != tc.want {
			t.Errorf("retryAfter(%q) = %q, want %q", tc.values, got, tc.want)
		}
	}
}
