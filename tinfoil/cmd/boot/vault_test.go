package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	wire "github.com/tinfoilsh/tinfoil-go/verifier/collaterals"

	shimconfig "tinfoil/internal/config"
	"tinfoil/internal/legacy"
)

func TestMergeVaultSecretsRequiresExactResponse(t *testing.T) {
	for _, test := range []struct {
		name    string
		secrets map[string]string
	}{
		{name: "missing", secrets: map[string]string{}},
		{name: "empty", secrets: map[string]string{"API_KEY": ""}},
		{name: "null", secrets: map[string]string{"API_KEY": "null"}},
		{name: "wrong name", secrets: map[string]string{"OTHER": "value"}},
		{name: "extra", secrets: map[string]string{"API_KEY": "value", "OTHER": "value"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := mergeVaultSecrets([]string{"API_KEY"}, test.secrets, &shimconfig.ExternalConfig{}); err == nil {
				t.Fatal("invalid Vault response accepted")
			}
		})
	}
}

func TestMergeVaultSecrets(t *testing.T) {
	external := &shimconfig.ExternalConfig{Secrets: map[string]string{"EXISTING": "value"}}
	if err := mergeVaultSecrets([]string{"API_KEY"}, map[string]string{"API_KEY": "secret"}, external); err != nil {
		t.Fatal(err)
	}
	if external.Secrets["API_KEY"] != "secret" || external.Secrets["EXISTING"] != "value" {
		t.Fatalf("external secrets = %#v", external.Secrets)
	}
}

func TestVaultChallengeAndFetchProtocol(t *testing.T) {
	nonce := strings.Repeat("01", 32)
	requests := 0
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests++
		switch request.URL.Path {
		case "/challenge":
			if request.Method != http.MethodPost {
				t.Fatalf("challenge method = %s", request.Method)
			}
			return jsonResponse(http.StatusOK, `{"nonce":"`+nonce+`"}`), nil
		case "/fetch":
			body, err := io.ReadAll(request.Body)
			if err != nil {
				t.Fatal(err)
			}
			var decoded map[string]json.RawMessage
			if err := json.Unmarshal(body, &decoded); err != nil {
				t.Fatal(err)
			}
			if _, found := decoded["token"]; found {
				t.Fatal("vault request carried a token")
			}
			if string(decoded["nonce"]) != `"`+nonce+`"` || string(decoded["repo"]) != `"tinfoilsh/workload"` {
				t.Fatalf("fetch request = %s", body)
			}
			return jsonResponse(http.StatusOK, `{"API_KEY":"secret"}`), nil
		default:
			t.Fatalf("unexpected path %s", request.URL.Path)
			return nil, nil
		}
	})}

	challenge, err := vaultChallenge(context.Background(), client, "https://vault.example")
	if err != nil {
		t.Fatal(err)
	}
	secrets, err := vaultFetch(context.Background(), client, "https://vault.example", vaultFetchRequest{
		Repo:       "tinfoilsh/workload",
		SecretRefs: []string{"API_KEY"},
		Nonce:      nonce,
		Document:   json.RawMessage(`{"format":"test"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(challenge) != 32 || secrets["API_KEY"] != "secret" || requests != 2 {
		t.Fatalf("challenge/secrets/requests = %d/%v/%d", len(challenge), secrets, requests)
	}
}

func TestVaultChallengeRejectsMalformedResponse(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusOK, `{"nonce":"00","extra":true}`), nil
	})}
	if _, err := vaultChallenge(context.Background(), client, "https://vault.example"); err == nil {
		t.Fatal("malformed challenge accepted")
	}
}

func TestVaultClientRejectsRedirects(t *testing.T) {
	client := vaultClient(tls.Certificate{})
	if err := client.CheckRedirect(&http.Request{}, nil); err != http.ErrUseLastResponse {
		t.Fatalf("redirect error = %v", err)
	}
}

func TestPrefetchVaultCollateral(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/attestation-collaterals" {
			t.Fatalf("path = %s", request.URL.Path)
		}
		var collateralRequest wire.Request
		if err := json.NewDecoder(request.Body).Decode(&collateralRequest); err != nil {
			t.Fatal(err)
		}
		if collateralRequest.Repo != "tinfoilsh/workload" || collateralRequest.Tag != "v1.2.3" || collateralRequest.Platform != "sev-snp" {
			t.Fatalf("request = %#v", collateralRequest)
		}
		_ = json.NewEncoder(w).Encode(wire.Response{
			Format:    wire.FormatV2,
			ExpiresAt: time.Now().Add(time.Hour),
		})
	}))
	defer server.Close()

	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write([]byte("raw quote")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	config := &Config{ShimCfg: &shimconfig.Config{ATC: server.URL}}
	external := &shimconfig.ExternalConfig{Metadata: shimconfig.Metadata{Repo: "tinfoilsh/workload", Tag: "v1.2.3"}}
	cpu := &CPUAttestation{V2Doc: &legacy.Document{
		Format: legacy.SevGuestV2,
		Body:   base64.StdEncoding.EncodeToString(compressed.Bytes()),
	}}
	collateral, err := prefetchVaultCollateral(context.Background(), config, external, cpu)
	if err != nil {
		t.Fatal(err)
	}
	if len(collateral) != 0 {
		t.Fatalf("collateral = %#v", collateral)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func jsonResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(http.Header),
	}
}
