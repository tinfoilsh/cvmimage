package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/tinfoilsh/encrypted-http-body-protocol/identity"

	tinfoilattestation "tinfoil/internal/attestation"
	"tinfoil/internal/config"
	"tinfoil/internal/key"
	"tinfoil/internal/key/online"
	"tinfoil/internal/legacy"
)

// TestOnlineValidationPreservesErrorsThroughEHBP pins that a control plane
// refusal reaches the client with its status, Retry-After and, for an
// OpenAI-style error, its message, while any other body stays private.
func TestOnlineValidationPreservesErrorsThroughEHBP(t *testing.T) {
	const privateDetail = "private control-plane detail"
	const pausedMessage = "API access is paused because this billing period's usage reached the account's usage limit."
	const keyLimitMessage = "Spend limit reached for this API key."
	const retryDate = "Wed, 21 Oct 2037 07:28:00 GMT"
	const origin = "https://client.example"
	cases := []struct {
		name        string
		status      int
		body        string
		retry       []string
		wantRetry   string
		wantType    string
		wantCode    string
		wantMessage string
	}{
		{name: "paused account", status: http.StatusPaymentRequired, body: `{"error":{"type":"insufficient_quota","code":"insufficient_quota","message":"` + pausedMessage + `"}}`, wantType: "insufficient_quota", wantCode: "insufficient_quota", wantMessage: pausedMessage},
		{name: "key limit", status: http.StatusTooManyRequests, body: `{"error":{"type":"insufficient_quota","code":"insufficient_quota","message":"` + keyLimitMessage + `"}}`, wantType: "insufficient_quota", wantCode: "insufficient_quota", wantMessage: keyLimitMessage},
		{name: "unauthorized", status: http.StatusUnauthorized, wantType: errTypeInvalidRequest},
		{name: "forbidden", status: http.StatusForbidden, wantType: errTypeInvalidRequest},
		{name: "payment", status: http.StatusPaymentRequired, wantType: key.ErrTypeInsufficientQuota},
		{name: "rate limit", status: http.StatusTooManyRequests, retry: []string{"42"}, wantRetry: "42", wantType: errTypeRateLimit},
		{name: "bad request", status: http.StatusBadRequest, wantType: errTypeInvalidRequest},
		{name: "not found", status: http.StatusNotFound, wantType: errTypeInvalidRequest},
		{name: "bad gateway", status: http.StatusBadGateway, wantType: errTypeServer},
		{name: "unavailable", status: http.StatusServiceUnavailable, retry: []string{"30"}, wantRetry: "30", wantType: errTypeServiceUnavailable},
		{name: "gateway timeout", status: http.StatusGatewayTimeout, wantType: errTypeServer},
		{name: "retry date", status: http.StatusServiceUnavailable, retry: []string{retryDate}, wantRetry: retryDate, wantType: errTypeServiceUnavailable},
		{name: "invalid retry", status: http.StatusServiceUnavailable, retry: []string{"-1"}, wantType: errTypeServiceUnavailable},
		{name: "duplicate retry", status: http.StatusServiceUnavailable, retry: []string{"10", "20"}, wantType: errTypeServiceUnavailable},
	}
	for _, tc := range cases {
		for _, encrypted := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/encrypted=%t", tc.name, encrypted), func(t *testing.T) {
				control := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					for _, value := range tc.retry {
						w.Header().Add("Retry-After", value)
					}
					w.WriteHeader(tc.status)
					if tc.body != "" {
						io.WriteString(w, tc.body)
					} else {
						io.WriteString(w, privateDetail)
					}
				}))
				defer control.Close()
				originalTransport := http.DefaultTransport
				http.DefaultTransport = control.Client().Transport
				defer func() { http.DefaultTransport = originalTransport }()
				validator, err := online.NewValidator(control.URL)
				if err != nil {
					t.Fatal(err)
				}
				id, err := identity.NewIdentity()
				if err != nil {
					t.Fatal(err)
				}
				handler := NewShimServer(validator, nil, &legacy.Document{}, tinfoilattestation.Identity{}, 0, id, nil, nil, &config.Config{}, &config.ExternalConfig{}, "", nil)
				req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader("{}"))
				req.Header.Set("Authorization", "Bearer test-key")
				req.Header.Set("Origin", origin)
				var requestContext *identity.RequestContext
				if encrypted {
					requestContext, err = id.EncryptRequestWithContext(req)
					if err != nil {
						t.Fatal(err)
					}
				}
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)
				resp := rec.Result()
				defer resp.Body.Close()
				if resp.StatusCode != tc.status || resp.Header.Get("Retry-After") != tc.wantRetry {
					t.Errorf("status/retry = %d/%q, want %d/%q", resp.StatusCode, resp.Header.Get("Retry-After"), tc.status, tc.wantRetry)
				}
				if resp.Header.Get("Access-Control-Allow-Origin") != origin || !slices.ContainsFunc(strings.Split(resp.Header.Get("Access-Control-Expose-Headers"), ","), func(header string) bool {
					return strings.EqualFold(strings.TrimSpace(header), "Retry-After")
				}) {
					t.Error("cross-origin clients cannot read Retry-After")
				}
				if encrypted {
					if json.Valid(rec.Body.Bytes()) {
						t.Fatal("EHBP error body is not encrypted")
					}
					if err := requestContext.DecryptResponse(resp); err != nil {
						t.Fatal(err)
					}
				}
				var body errorEnvelope
				if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
					t.Fatal(err)
				}
				code := ""
				if body.Error.Code != nil {
					code = *body.Error.Code
				}
				if body.Error.Type != tc.wantType || code != tc.wantCode {
					t.Errorf("type/code = %s/%s, want %s/%s", body.Error.Type, code, tc.wantType, tc.wantCode)
				}
				wantMessage := tc.wantMessage
				if wantMessage == "" {
					wantMessage = http.StatusText(tc.status)
				}
				if body.Error.Message != wantMessage {
					t.Errorf("message = %q, want %q", body.Error.Message, wantMessage)
				}
			})
		}
	}
}
