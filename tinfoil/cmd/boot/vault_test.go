package main

import (
	"testing"

	shimconfig "tinfoil/internal/config"
)

func TestMergeVaultSecretsRequiresExactResponse(t *testing.T) {
	for _, test := range []struct {
		name    string
		secrets map[string]string
	}{
		{name: "missing", secrets: map[string]string{}},
		{name: "empty", secrets: map[string]string{"API_KEY": ""}},
		{name: "null", secrets: map[string]string{"API_KEY": "null"}},
		{name: "wrong name", secrets: map[string]string{"OTHER": "value"}},
		{name: "extra", secrets: map[string]string{"API_KEY": "value", "OTHER": "value"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := mergeVaultSecrets([]string{"API_KEY"}, test.secrets, &shimconfig.ExternalConfig{}); err == nil {
				t.Fatal("invalid Vault response accepted")
			}
		})
	}
}

func TestMergeVaultSecrets(t *testing.T) {
	external := &shimconfig.ExternalConfig{Secrets: map[string]string{"EXISTING": "value"}}
	if err := mergeVaultSecrets([]string{"API_KEY"}, map[string]string{"API_KEY": "secret"}, external); err != nil {
		t.Fatal(err)
	}
	if external.Secrets["API_KEY"] != "secret" || external.Secrets["EXISTING"] != "value" {
		t.Fatalf("external secrets = %#v", external.Secrets)
	}
}
