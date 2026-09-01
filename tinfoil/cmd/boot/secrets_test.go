package main

import (
	"context"
	"os"
	"strings"
	"testing"

	shimconfig "tinfoil/internal/config"
	"tinfoil/internal/secretstore"
)

func newHandoff(t *testing.T) *os.File {
	t.Helper()
	handoff, err := secretstore.NewHandoffFile()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { handoff.Close() })
	return handoff
}

func noFetch(t *testing.T) keyserverFetcher {
	return func(context.Context, []string) (map[string]string, error) {
		t.Fatal("keyserver fetch attempted")
		return nil, nil
	}
}

func TestPrepareSecretHandoff(t *testing.T) {
	config := &Config{
		Containers: []Container{{Secrets: []string{"API_KEY"}}},
	}
	externalConfig := &shimconfig.ExternalConfig{
		Secrets: map[string]string{"API_KEY": "secret"},
	}
	handoff := newHandoff(t)

	detail, err := prepareSecretHandoff(context.Background(), config, externalConfig, handoff, "config-digest", false, noFetch(t))
	if err != nil {
		t.Fatal(err)
	}
	if detail != "handed off 1 workload secret(s); keyserver not configured" {
		t.Fatalf("detail = %q", detail)
	}
	store, err := secretstore.ReadHandoff(handoff, "config-digest", []string{"API_KEY"})
	if err != nil {
		t.Fatal(err)
	}
	if store["API_KEY"] != "secret" {
		t.Fatalf("secret handoff = %#v", store)
	}
}

func TestPrepareSecretHandoffRejectsUnresolvedSecrets(t *testing.T) {
	config := &Config{
		Containers: []Container{{Secrets: []string{"API_KEY"}}},
	}
	_, err := prepareSecretHandoff(context.Background(), config, &shimconfig.ExternalConfig{}, newHandoff(t), "config-digest", false, noFetch(t))
	if err == nil || !strings.Contains(err.Error(), "1 declared secret(s) remain unresolved") {
		t.Fatalf("error = %v", err)
	}
}

func TestPrepareSecretHandoffReportsHandoffFailure(t *testing.T) {
	_, err := prepareSecretHandoff(context.Background(), &Config{}, &shimconfig.ExternalConfig{}, nil, "config-digest", false, noFetch(t))
	if err == nil || !strings.Contains(err.Error(), "creating sealed secret handoff") {
		t.Fatalf("error = %v", err)
	}
}

func TestPrepareSecretHandoffKeyserverFetchesEveryDeclaredSecret(t *testing.T) {
	config := &Config{
		KeyserverURL: "https://keys.example",
		Models:       []ModelSpec{{Name: "model", KeySecret: "MODEL_KEY"}},
		Containers:   []Container{{Secrets: []string{"API_KEY"}}},
	}
	externalConfig := &shimconfig.ExternalConfig{}
	handoff := newHandoff(t)

	var requested []string
	fetch := func(_ context.Context, names []string) (map[string]string, error) {
		requested = append(requested, names...)
		return map[string]string{"API_KEY": "secret", "MODEL_KEY": "key"}, nil
	}
	detail, err := prepareSecretHandoff(context.Background(), config, externalConfig, handoff, "config-digest", false, fetch)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(requested, ",") != "API_KEY,MODEL_KEY" {
		t.Fatalf("requested = %v, want every declared secret", requested)
	}
	if detail != "handed off 1 workload secret(s); fetched 2 from keyserver" {
		t.Fatalf("detail = %q", detail)
	}
	if externalConfig.GetSecret("MODEL_KEY") != "key" {
		t.Fatalf("model key not merged for boot: %#v", externalConfig.Secrets)
	}
	store, err := secretstore.ReadHandoff(handoff, "config-digest", []string{"API_KEY"})
	if err != nil {
		t.Fatal(err)
	}
	if store["API_KEY"] != "secret" {
		t.Fatalf("secret handoff = %#v", store)
	}
}

func TestPrepareSecretHandoffKeyserverRejectsHostSuppliedSecret(t *testing.T) {
	config := &Config{
		KeyserverURL: "https://keys.example",
		Containers:   []Container{{Secrets: []string{"API_KEY"}}},
	}
	externalConfig := &shimconfig.ExternalConfig{
		Secrets: map[string]string{"API_KEY": "from-host"},
	}
	_, err := prepareSecretHandoff(context.Background(), config, externalConfig, newHandoff(t), "config-digest", false, noFetch(t))
	if err == nil || !strings.Contains(err.Error(), "must come from the keyserver") {
		t.Fatalf("error = %v", err)
	}
}

func TestPrepareSecretHandoffDebugIgnoresKeyserver(t *testing.T) {
	config := &Config{
		KeyserverURL: "https://keys.example",
		Containers:   []Container{{Secrets: []string{"API_KEY"}}},
	}
	externalConfig := &shimconfig.ExternalConfig{
		Secrets: map[string]string{"API_KEY": "secret"},
	}
	detail, err := prepareSecretHandoff(context.Background(), config, externalConfig, newHandoff(t), "config-digest", true, noFetch(t))
	if err != nil {
		t.Fatal(err)
	}
	if detail != "handed off 1 workload secret(s); debug enclave: keyserver-url ignored, secrets supplied by host" {
		t.Fatalf("detail = %q", detail)
	}
}
