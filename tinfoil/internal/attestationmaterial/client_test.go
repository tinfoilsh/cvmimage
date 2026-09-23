package attestationmaterial

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	wire "github.com/tinfoilsh/tinfoil-go/verifier/collaterals"
)

func TestClientFetch(t *testing.T) {
	wantRequest := wire.Request{Repo: "tinfoilsh/example", Tag: "v1.2.3", Platform: "sev-snp", QuoteBase64: "cXVvdGU="}
	wantResponse := wire.Response{Format: wire.FormatV2, ExpiresAt: time.Now().Add(time.Hour).UTC()}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/attestation-collaterals" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		var got wire.Request
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatalf("decoding request: %v", err)
		}
		if got != wantRequest {
			t.Fatalf("request = %#v, want %#v", got, wantRequest)
		}
		json.NewEncoder(w).Encode(wantResponse)
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "", "", server.Client())
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	got, err := client.Fetch(context.Background(), wantRequest)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if !got.ExpiresAt.Equal(wantResponse.ExpiresAt) || got.Format != wantResponse.Format {
		t.Fatalf("response = %#v, want %#v", got, wantResponse)
	}
}

func TestClientRejectsExpiredResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(wire.Response{Format: wire.FormatV2, ExpiresAt: time.Now().Add(-time.Minute)})
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "", "", server.Client())
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := client.Fetch(context.Background(), wire.Request{}); err == nil {
		t.Fatal("Fetch accepted expired response")
	}
}

func TestNewClientRejectsInvalidURL(t *testing.T) {
	if _, err := NewClient("unix:///run/atc.sock", "", "", nil); err == nil {
		t.Fatal("NewClient accepted non-HTTP URL")
	}
	if _, err := NewClient("http://:8085", "", "", nil); err == nil {
		t.Fatal("NewClient accepted URL without a hostname")
	}
}

func TestClientRenewsTokenAcrossRestarts(t *testing.T) {
	const initialToken = "initial-token"
	const renewedToken = "renewed-token"
	tokenPath := filepath.Join(t.TempDir(), "token")
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		wantToken := initialToken
		if requests > 1 {
			wantToken = renewedToken
		}
		if got := r.Header.Get("Authorization"); got != "Bearer "+wantToken {
			t.Errorf("Authorization = %q, want token %q", got, wantToken)
		}
		w.Header().Set(collateralTokenHeader, renewedToken)
		json.NewEncoder(w).Encode(wire.Response{Format: wire.FormatV2, ExpiresAt: time.Now().Add(time.Hour)})
	}))
	defer server.Close()

	for range 2 {
		client, err := NewClient(server.URL, initialToken, tokenPath, server.Client())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := client.Fetch(context.Background(), wire.Request{Repo: "owner/private"}); err != nil {
			t.Fatal(err)
		}
	}
	if requests != 2 {
		t.Fatalf("requests = %d", requests)
	}
	data, err := os.ReadFile(tokenPath)
	if err != nil || string(data) != renewedToken {
		t.Fatalf("stored token = %q, err = %v", data, err)
	}
	info, err := os.Stat(tokenPath)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("token file mode is not private: %v, %v", info, err)
	}
}

func TestAuthenticatedClientRejectsPlaintextAndRedirects(t *testing.T) {
	tokenPath := filepath.Join(t.TempDir(), "token")
	if _, err := NewClient("http://atc.example", "token", tokenPath, nil); err == nil {
		t.Fatal("authenticated client accepted plaintext HTTP")
	}
	redirected := false
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirected = true
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()
	source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer source.Close()
	client, err := NewClient(source.URL, "token", tokenPath, source.Client())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Fetch(context.Background(), wire.Request{}); err == nil {
		t.Fatal("authenticated client followed redirect")
	}
	if redirected {
		t.Fatal("redirect target received a request")
	}
}

func TestClientDoesNotSaveRenewalFromRejectedResponse(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusOK} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			tokenPath := filepath.Join(t.TempDir(), "token")
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set(collateralTokenHeader, "rejected-token")
				w.WriteHeader(status)
				json.NewEncoder(w).Encode(wire.Response{Format: wire.FormatV2, ExpiresAt: time.Now().Add(-time.Minute)})
			}))
			defer server.Close()
			client, err := NewClient(server.URL, "initial-token", tokenPath, server.Client())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.Fetch(context.Background(), wire.Request{}); err == nil {
				t.Fatal("accepted rejected response")
			}
			if _, err := os.Stat(tokenPath); !os.IsNotExist(err) {
				t.Fatalf("rejected token was saved: %v", err)
			}
		})
	}
}
