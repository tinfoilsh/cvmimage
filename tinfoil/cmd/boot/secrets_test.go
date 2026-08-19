package main

import (
	"context"
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

	detail, err := prepareSecretHandoff(context.Background(), config, externalConfig, handoff, "config-digest", nil, nil)
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

	_, err = prepareSecretHandoff(context.Background(), config, &shimconfig.ExternalConfig{}, handoff, "config-digest", nil, nil)
	if err == nil || !strings.Contains(err.Error(), "1 declared secret(s) remain unresolved") {
		t.Fatalf("error = %v", err)
	}
}

func TestPrepareSecretHandoffReportsHandoffFailure(t *testing.T) {
	_, err := prepareSecretHandoff(context.Background(), &Config{}, &shimconfig.ExternalConfig{}, nil, "config-digest", nil, nil)
	if err == nil || !strings.Contains(err.Error(), "creating sealed secret handoff") {
		t.Fatalf("error = %v", err)
	}
}
