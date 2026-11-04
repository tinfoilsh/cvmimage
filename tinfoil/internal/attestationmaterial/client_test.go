package attestationmaterial

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/tinfoilsh/tinfoil-go/verify/document/collateral"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	wire "github.com/tinfoilsh/tinfoil-go/collaterals"
)

func TestRegistryCredentialRequiresTrustedTLS(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
	}))
	defer server.Close()
	client, err := NewClient(server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.UseRegistryCredential("scoped-token"); err != nil {
		t.Fatal(err)
	}
	_, err = client.Fetch(t.Context(), Request{Version: RequestVersionDocument, Profile: wire.FormatV3, Document: json.RawMessage(`{}`), Repo: "org/app", Tag: "v1", Digest: strings.Repeat("a", 64)})
	var untrusted x509.UnknownAuthorityError
	if !errors.As(err, &untrusted) || requests.Load() != 0 {
		t.Fatalf("credential reached an untrusted TLS peer: requests=%d error=%v", requests.Load(), err)
	}
}

func TestRegistryCredentialIsReusedAcrossFetches(t *testing.T) {
	request := Request{Version: RequestVersionDocument, Profile: wire.FormatV3, Document: json.RawMessage(`{}`), Repo: "org/app", Tag: "v1", Digest: strings.Repeat("a", 64)}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer boot-token" {
			t.Error("wrong registry credential")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		if _, exists := body["registry_token"]; exists {
			t.Error("credential must not enter collateral JSON")
		}
		json.NewEncoder(w).Encode(wire.Response{Format: wire.FormatV3, ExpiresAt: time.Now().Add(time.Hour).UTC()})
	}))
	defer server.Close()
	client, err := NewClient(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if err := client.UseRegistryCredential("boot-token"); err != nil {
		t.Fatal(err)
	}
	for range 2 {
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

	}
}

func TestRegistryCredentialRejectsRedirectsAndPlaintextOrigins(t *testing.T) {
	for _, base := range []string{
		"https://user:password@atc.example", "https://atc.example?", "https://atc.example?token=value", "https://atc.example#fragment",
		"http://8.8.8.8", "http://100.64.0.1:8085", "http://10.0.0.1:8085", "http://[fc00::1]:8085",
		"http://localhost:8085", "http://127.0.0.1:8085", "http://[::1]:8085", "http://atc.example",
	} {
		client, err := NewClient(base, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := client.UseRegistryCredential("token"); err == nil || client.registryToken != "" {
			t.Errorf("accepted unsafe credential origin %s", base)
		}
	}
	for _, base := range []string{"https://atc.example", "https://100.64.0.1:8085", "https://10.0.0.1:8085", "https://[::1]:8085"} {
		client, err := NewClient(base, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := client.UseRegistryCredential("token"); err != nil {
			t.Fatalf("rejected supported credential origin %s: %v", base, err)
		}
	}
	calls := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		http.Redirect(w, r, "/other", http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	client, err := NewClient(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if err := client.UseRegistryCredential("token"); err != nil {
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

func TestConfigAttachmentFollowsMeasuredDisclosurePolicy(t *testing.T) {
	for _, include := range []bool{false, true} {
		for _, local := range []bool{false, true} {
			t.Run(fmt.Sprintf("include=%t/local=%t", include, local), func(t *testing.T) {
				runtime := "v0.15.3-rc.1@sha256:" + strings.Repeat("a", 64)
				config := []byte("cvm-version: " + runtime + "\nsecurity:\n  include-config-in-attestation: " + fmt.Sprint(include) + "\n")
				digest := sha256.Sum256(config)
				request := Request{Version: RequestVersionDocument, Profile: wire.FormatV3, Document: json.RawMessage(`{}`), Repo: "org/app", Tag: "v1", Digest: hex.EncodeToString(digest[:])}
				if local {
					request.Repo, request.Tag, request.Runtime = "", "", runtime
				}
				original, err := json.Marshal(map[string]any{"endorsement_ref": "sha256:" + strings.Repeat("b", 64), "sigstore_bundle": map[string]string{"mediaType": "fixture"}, "issuer_certificate_der": []byte("issuer"), "config_base64": []byte("unsolicited config")})
				if err != nil {
					t.Fatal(err)
				}
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					var got map[string]json.RawMessage
					if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
						t.Error(err)
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					if _, ok := got["config_base64"]; ok {
						t.Error("disclosure attachment was sent to ATC")
					}
					response := wire.Response{Format: wire.FormatV3, ExpiresAt: time.Now().Add(time.Hour)}
					if !local {
						response.Collateral = []collateral.Entry{{ID: collateral.ConfigID, Role: collateral.RoleReferenceValues, Format: collateral.ConfigEndorsementV2Format, Data: original}}
					}
					if err := json.NewEncoder(w).Encode(response); err != nil {
						t.Error(err)
					}
				}))
				defer server.Close()
				client, err := NewClient(server.URL, server.Client())
				if err != nil {
					t.Fatal(err)
				}
				path := filepath.Join(t.TempDir(), "config.yml")
				if err := os.WriteFile(path, config, 0600); err != nil {
					t.Fatal(err)
				}
				if err := client.UseConfigFile(path); err != nil {
					t.Fatal(err)
				}
				response, err := client.Fetch(t.Context(), request)
				if err != nil {
					t.Fatal(err)
				}
				if local && !include {
					if len(response.Collateral) != 0 {
						t.Fatal("unexpected local config attachment")
					}
					return
				}
				set, err := collateral.Decode(response.Collateral)
				if err != nil {
					t.Fatal(err)
				}
				if include && !bytes.Equal(set.Config.Config, config) {
					t.Fatal("config attachment lost exact bytes")
				}
				if !include && len(set.Config.Config) != 0 {
					t.Fatal("config disclosed despite omission policy")
				}
				if !local && (set.Config.Reference != "sha256:"+strings.Repeat("b", 64) || !bytes.Equal(set.Config.Issuer, []byte("issuer")) || len(set.Config.Bundle) == 0) {
					t.Fatal("attachment changed endorsement evidence")
				}
			})
		}
	}
}
