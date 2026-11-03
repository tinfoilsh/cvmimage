package attestationmaterial

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	wire "github.com/tinfoilsh/tinfoil-go/collaterals"
)

func TestPrivateHTTPCredentialBypassesProxies(t *testing.T) {
	proxyCalls := 0
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyCalls++
		w.WriteHeader(http.StatusForbidden)
	}))
	defer proxy.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer scoped-token" {
			t.Error("missing scoped credential")
		}
		w.Header().Set(RegistryTokenHeader, "renewed-token")
		json.NewEncoder(w).Encode(wire.Response{Format: wire.FormatV3, ExpiresAt: time.Now().Add(time.Hour).UTC()})
	}))
	defer origin.Close()
	proxyURL, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = http.ProxyURL(proxyURL)
	defer transport.CloseIdleConnections()
	client, err := NewClient(origin.URL, &http.Client{Transport: transport})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.UseRegistryCredential("scoped-token", filepath.Join(t.TempDir(), "token")); err != nil {
		t.Fatal(err)
	}
	defer client.http.CloseIdleConnections()
	_, err = client.Fetch(t.Context(), Request{Version: RequestVersionDocument, Profile: wire.FormatV3, Document: json.RawMessage(`{}`), Repo: "org/app", Tag: "v1", Digest: strings.Repeat("a", 64)})
	if err != nil {
		t.Fatal(err)
	}
	if proxyCalls != 0 {
		t.Fatal("registry credential was sent through the proxy")
	}
}

func TestRegistryCredentialRefreshSurvivesClientRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	request := Request{Version: RequestVersionDocument, Profile: wire.FormatV3, Document: json.RawMessage(`{}`), Repo: "org/app", Tag: "v1", Digest: strings.Repeat("a", 64)}
	expected := "boot-token"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+expected {
			t.Error("wrong registry credential")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		if _, exists := body["registry_token"]; exists {
			t.Error("credential must not enter collateral JSON")
		}
		w.Header().Set(RegistryTokenHeader, "refreshed-token")
		json.NewEncoder(w).Encode(wire.Response{Format: wire.FormatV3, ExpiresAt: time.Now().Add(time.Hour).UTC()})
	}))
	defer server.Close()
	for range 2 {
		client, err := NewClient(server.URL, server.Client())
		if err != nil {
			t.Fatal(err)
		}
		if err := client.UseRegistryCredential("boot-token", path); err != nil {
			t.Fatal(err)
		}
		response, err := client.Fetch(t.Context(), request)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := json.Marshal(response)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(encoded), "token") {
			t.Fatal("credential exposed in response")
		}
		persisted, err := os.ReadFile(path)
		if err != nil || string(persisted) != "refreshed-token" {
			t.Fatalf("persisted credential: %v", err)
		}
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatal("credential file must be private")
		}
		expected = "refreshed-token"
	}
}

func TestRegistryCredentialRejectsRedirectsAndPlaintextRemoteOrigins(t *testing.T) {
	for _, base := range []string{"https://user:password@atc.example", "https://atc.example?", "https://atc.example?token=value", "https://atc.example#fragment", "http://8.8.8.8"} {
		client, err := NewClient(base, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := client.UseRegistryCredential("token", filepath.Join(t.TempDir(), "token")); err == nil {
			t.Fatalf("accepted unsafe credential origin %s", base)
		}
	}
	for _, base := range []string{"https://atc.example", "http://100.64.0.1:8085", "http://10.0.0.1:8085", "http://[::1]:8085"} {
		client, err := NewClient(base, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := client.UseRegistryCredential("token", filepath.Join(t.TempDir(), "token")); err != nil {
			t.Fatalf("rejected supported credential origin %s: %v", base, err)
		}
	}
	client, err := NewClient("http://atc.example", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.UseRegistryCredential("token", filepath.Join(t.TempDir(), "token")); err == nil {
		t.Fatal("accepted plaintext credential delivery")
	}
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		http.Redirect(w, r, "/other", http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	client, err = NewClient(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if err := client.UseRegistryCredential("token", filepath.Join(t.TempDir(), "token")); err != nil {
		t.Fatal(err)
	}
	_, err = client.Fetch(t.Context(), Request{Version: RequestVersionDocument, Profile: wire.FormatV3, Document: json.RawMessage(`{}`), Repo: "org/app", Tag: "v1", Digest: strings.Repeat("a", 64)})
	if err == nil || calls != 1 {
		t.Fatalf("redirect followed: calls=%d error=%v", calls, err)
	}
}

func TestClientFetch(t *testing.T) {
	for _, tc := range []struct {
		name    string
		format  string
		wantErr string
	}{
		{name: "registry", format: wire.FormatV3},
		{name: "rejects v2", format: wire.FormatV2, wantErr: "unexpected collaterals format"},
		{name: "rejects missing format", wantErr: "unexpected collaterals format"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wantRequest := Request{Version: RequestVersionDocument, Profile: wire.FormatV3, Document: json.RawMessage(`{}`), Repo: "tinfoilsh/example", Tag: "v1.2.3", Digest: strings.Repeat("b", 64)}
			wantResponse := wire.Response{Format: tc.format, ExpiresAt: time.Now().Add(time.Hour).UTC()}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/attestation-collaterals" {
					t.Errorf("path = %q", r.URL.Path)
				}
				var got Request
				if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
					t.Errorf("decoding request: %v", err)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				if !reflect.DeepEqual(got, wantRequest) {
					t.Errorf("request = %#v, want %#v", got, wantRequest)
				}
				json.NewEncoder(w).Encode(wantResponse)
			}))
			defer server.Close()

			client, err := NewClient(server.URL, server.Client())
			if err != nil {
				t.Fatalf("NewClient: %v", err)
			}
			got, err := client.Fetch(context.Background(), wantRequest)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("Fetch error = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Fetch: %v", err)
			}
			if !got.ExpiresAt.Equal(wantResponse.ExpiresAt) || got.Format != wantResponse.Format {
				t.Fatalf("response = %#v, want %#v", got, wantResponse)
			}
		})
	}
}

func TestClientRejectsExpiredResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(wire.Response{Format: wire.FormatV3, ExpiresAt: time.Now().Add(-time.Minute)})
	}))
	defer server.Close()

	client, err := NewClient(server.URL, server.Client())
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := client.Fetch(context.Background(), Request{Version: RequestVersionDocument, Profile: wire.FormatV3, Document: json.RawMessage(`{}`), Config: []byte("config")}); err == nil || !strings.Contains(err.Error(), "expired") {
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
	_, err = client.Fetch(context.Background(), Request{Version: RequestVersionDocument, Profile: wire.FormatV3, Config: []byte("config"), Document: json.RawMessage(`{}`)})
	if err == nil || !strings.Contains(err.Error(), "unsupported version") || requests != 1 {
		t.Fatalf("requests=%d, error=%v", requests, err)
	}
}
