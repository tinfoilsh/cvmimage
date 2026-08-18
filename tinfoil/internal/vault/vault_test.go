package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	shimconfig "tinfoil/internal/config"
	"tinfoil/internal/runtimeconfig"
)

func configWithSecrets(secrets ...[]string) *runtimeconfig.Config {
	config := &runtimeconfig.Config{VaultURL: "https://vault.example.com"}
	for i, names := range secrets {
		config.Containers = append(config.Containers, runtimeconfig.Container{
			Name:    "c" + string(rune('a'+i)),
			Secrets: names,
		})
	}
	return config
}

func TestMissingSecretValues(t *testing.T) {
	config := configWithSecrets(
		[]string{"DB_PASSWORD", "API_KEY", "DB_PASSWORD"},
		[]string{"API_KEY", "STRIPE_KEY"},
	)
	ext := &shimconfig.ExternalConfig{Secrets: map[string]string{"API_KEY": "populated"}}

	got := missingSecretValues(config, ext)
	want := []string{"DB_PASSWORD", "STRIPE_KEY"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("missingSecretValues = %v, want %v", got, want)
	}
}

func TestFetchSecretsAllPopulated(t *testing.T) {
	config := configWithSecrets([]string{"API_KEY"})
	ext := &shimconfig.ExternalConfig{Secrets: map[string]string{"API_KEY": "populated"}}
	if err := FetchSecrets(config, ext); err != nil {
		t.Fatalf("FetchSecrets with populated secrets: %v", err)
	}
}

func TestFetchSecretsRequiresToken(t *testing.T) {
	config := configWithSecrets([]string{"API_KEY"})
	if err := FetchSecrets(config, &shimconfig.ExternalConfig{}); err == nil {
		t.Fatal("FetchSecrets without vault-token succeeded")
	}
}

func TestFetchSecretsRequiresHTTPS(t *testing.T) {
	config := configWithSecrets([]string{"API_KEY"})
	config.VaultURL = "http://vault.example.com"
	ext := &shimconfig.ExternalConfig{VaultToken: "token"}
	if err := FetchSecrets(config, ext); err == nil {
		t.Fatal("FetchSecrets with http vault-url succeeded")
	}
}

func TestFetch(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/fetch" {
			t.Errorf("path = %q, want /fetch", r.URL.Path)
		}
		var req fetchRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decoding request: %v", err)
		}
		if req.Repo != "org/repo" || req.Token != "token" {
			t.Errorf("request repo=%q token=%q", req.Repo, req.Token)
		}
		if !reflect.DeepEqual(req.SecretRefs, []string{"DB_PASSWORD"}) {
			t.Errorf("secret_refs = %v", req.SecretRefs)
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"DB_PASSWORD": "hunter2"})
	}))
	defer server.Close()

	secrets, err := fetch(server.Client(), server.URL+"/", fetchRequest{
		Repo:       "org/repo",
		SecretRefs: []string{"DB_PASSWORD"},
		Token:      "token",
	})
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if secrets["DB_PASSWORD"] != "hunter2" {
		t.Fatalf("secrets = %v", secrets)
	}
}

func TestFetchNonOK(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "measurement not in policy", http.StatusForbidden)
	}))
	defer server.Close()

	if _, err := fetch(server.Client(), server.URL, fetchRequest{}); err == nil {
		t.Fatal("fetch with 403 response succeeded")
	}
}
