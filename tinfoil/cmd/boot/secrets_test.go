package main

import (
	"strings"
	"testing"

	shimconfig "tinfoil/internal/config"
	"tinfoil/internal/secretstore"
)

func TestPrepareSecretHandoff(t *testing.T) {
	config := &Config{
		Containers: []Container{{Secrets: []string{"API_KEY"}}},
	}
	externalConfig := &shimconfig.ExternalConfig{
		Secrets: map[string]string{"API_KEY": "secret"},
	}
	handoff, err := secretstore.NewHandoffFile()
	if err != nil {
		t.Fatal(err)
	}
	defer handoff.Close()

	detail, err := prepareSecretHandoff(config, externalConfig, handoff, "config-digest")
	if err != nil {
		t.Fatal(err)
	}
	if detail != "handed off 1 workload secret(s); vault not configured" {
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
	handoff, err := secretstore.NewHandoffFile()
	if err != nil {
		t.Fatal(err)
	}
	defer handoff.Close()

	_, err = prepareSecretHandoff(config, &shimconfig.ExternalConfig{}, handoff, "config-digest")
	if err == nil || !strings.Contains(err.Error(), "1 declared secret(s) remain unresolved") {
		t.Fatalf("error = %v", err)
	}
}
