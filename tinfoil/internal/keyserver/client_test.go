package keyserver

import (
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
)

func TestKeyserverChallengeAndFetchProtocol(t *testing.T) {
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
				t.Fatal("keyserver request carried a token")
			}
			if string(decoded["nonce"]) != `"`+nonce+`"` ||
				string(decoded["repo"]) != `"tinfoilsh/workload"` ||
				string(decoded["secret_refs"]) != `["API_KEY"]` ||
				string(decoded["document"]) != `{"format":"test"}` {
				t.Fatalf("fetch request = %s", body)
			}
			return jsonResponse(http.StatusOK, `{"API_KEY":"secret"}`), nil
		default:
			t.Fatalf("unexpected path %s", request.URL.Path)
			return nil, nil
		}
	})}

	challenge, err := keyserverChallenge(context.Background(), client, "https://keyserver.example")
	if err != nil {
		t.Fatal(err)
	}
	secrets, err := keyserverFetch(context.Background(), client, "https://keyserver.example", keyserverFetchRequest{
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

func TestKeyserverChallengeRejectsMalformedResponse(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusOK, `{"nonce":"00","extra":true}`), nil
	})}
	if _, err := keyserverChallenge(context.Background(), client, "https://keyserver.example"); err == nil {
		t.Fatal("malformed challenge accepted")
	}
}

func TestKeyserverClientRejectsRedirects(t *testing.T) {
	client := keyserverClient(tls.Certificate{})
	if err := client.CheckRedirect(&http.Request{}, nil); err != http.ErrUseLastResponse {
		t.Fatalf("redirect error = %v", err)
	}
}

func TestPrefetchKeyserverCollateral(t *testing.T) {
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
		quote, err := base64.StdEncoding.DecodeString(collateralRequest.QuoteBase64)
		if err != nil || string(quote) != "raw quote" {
			t.Fatalf("quote = %q, err = %v", quote, err)
		}
		_ = json.NewEncoder(w).Encode(wire.Response{
			Format:    wire.FormatV2,
			ExpiresAt: time.Now().Add(time.Hour),
		})
	}))
	defer server.Close()

	collateralRequest := wire.Request{Repo: "tinfoilsh/workload", Tag: "v1.2.3", Platform: "sev-snp", QuoteBase64: base64.StdEncoding.EncodeToString([]byte("raw quote"))}
	collateral, err := prefetchKeyserverCollateral(context.Background(), server.URL, collateralRequest)
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
