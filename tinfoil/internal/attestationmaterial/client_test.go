package attestationmaterial

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

	client, err := NewClient(server.URL, server.Client())
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

	client, err := NewClient(server.URL, server.Client())
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := client.Fetch(context.Background(), wire.Request{}); err == nil {
		t.Fatal("Fetch accepted expired response")
	}
}

func TestNewClientRejectsInvalidURL(t *testing.T) {
	if _, err := NewClient("unix:///run/atc.sock", nil); err == nil {
		t.Fatal("NewClient accepted non-HTTP URL")
	}
}
