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
	"github.com/tinfoilsh/tinfoil-go/document/collateral"
)

func TestClientFetch(t *testing.T) {
	for _, tc := range []struct {
		name    string
		profile string
		format  string
		wantErr string
	}{
		{name: "legacy", format: wire.FormatV2},
		{name: "v3", profile: wire.FormatV3, format: wire.FormatV3},
		{name: "legacy rejects v3", format: wire.FormatV3, wantErr: "unexpected collaterals format"},
		{name: "v3 rejects v2", profile: wire.FormatV3, format: wire.FormatV2, wantErr: "unexpected collaterals format"},
		{name: "v3 rejects missing format", profile: wire.FormatV3, wantErr: "unexpected collaterals format"},
		{name: "unsupported profile", profile: "unsupported", format: wire.FormatV2, wantErr: "unsupported collateral request profile"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wantRequest := wire.Request{Profile: tc.profile, Repo: "tinfoilsh/example", Tag: "v1.2.3", Platform: "sev-snp", QuoteBase64: "cXVvdGU="}
			if tc.profile == wire.FormatV3 {
				wantRequest.Repo, wantRequest.Tag = "", ""
				wantRequest.Runtime = &collateral.RuntimeReference{Repo: "tinfoilsh/cvmimage", Tag: "v1.2.3", Digest: strings.Repeat("a", 64)}
				wantRequest.Config = &collateral.ConfigReference{Name: "/org/project/v1.2.3", Digest: strings.Repeat("b", 64)}
			}
			wantResponse := wire.Response{Format: tc.format, ExpiresAt: time.Now().Add(time.Hour).UTC()}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/attestation-collaterals" {
					t.Errorf("path = %q", r.URL.Path)
				}
				var got wire.Request
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
	if _, err := NewClient("http://:8085", nil); err == nil {
		t.Fatal("NewClient accepted URL without a hostname")
	}
}
