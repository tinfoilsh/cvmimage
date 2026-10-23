package attestationmaterial

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	wire "github.com/tinfoilsh/tinfoil-go/collaterals"
	"github.com/tinfoilsh/tinfoil-go/document"
)

func TestClientFetch(t *testing.T) {
	nonce := make([]byte, document.NonceSize)
	empty, err := document.Build(document.BuildInput{Nonce: nonce}, func([64]byte) (string, []byte, error) {
		return document.SEVSNPReportV1Format, []byte("quote"), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	wantRequest := Request{Version: RequestVersionDocument, Repo: "tinfoilsh/example", Tag: "v1.2.3", Document: empty}
	wantResponse := wire.Response{Format: wire.FormatV2, ExpiresAt: time.Now().Add(time.Hour).UTC()}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/attestation-collaterals" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		var got Request
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatalf("decoding request: %v", err)
		}
		if !reflect.DeepEqual(got, wantRequest) {
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
	if _, err := client.Fetch(context.Background(), Request{Version: RequestVersionDocument, Repo: "repo", Document: json.RawMessage(`{}`)}); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expected expired response error, got %v", err)
	}
}

func TestNewClientRejectsInvalidURL(t *testing.T) {
	if _, err := NewClient("unix:///run/atc.sock", nil); err == nil {
		t.Fatal("NewClient accepted non-HTTP URL")
	}
	if _, err := NewClient("http://:8085", nil); err == nil {
		t.Fatal("NewClient accepted URL without a hostname")
	}
}

func TestClientDoesNotDowngradeRejectedDocument(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		var request Request
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		if request.Version != RequestVersionDocument {
			t.Fatal("request was downgraded")
		}
		http.Error(w, "unsupported version", http.StatusBadRequest)
	}))
	defer server.Close()
	client, err := NewClient(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Fetch(context.Background(), Request{Version: RequestVersionDocument, Repo: "org/repo", Document: json.RawMessage(`{}`)})
	if err == nil || !strings.Contains(err.Error(), "unsupported version") || requests != 1 {
		t.Fatalf("requests=%d, error=%v", requests, err)
	}
}
