package config

import (
	"testing"
)

func TestGetSecret(t *testing.T) {
	tests := []struct {
		name   string
		config *ExternalConfig
		key    string
		want   string
	}{
		{"nil receiver", nil, "KEY", ""},
		{"nil secrets map", &ExternalConfig{}, "KEY", ""},
		{"missing key", &ExternalConfig{Secrets: map[string]string{"A": "1"}}, "B", ""},
		{"found key", &ExternalConfig{Secrets: map[string]string{"A": "1"}}, "A", "1"},
		{"null value filtered", &ExternalConfig{Secrets: map[string]string{"A": "null"}}, "A", ""},
		{"empty value returned", &ExternalConfig{Secrets: map[string]string{"A": ""}}, "A", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.config.GetSecret(tt.key)
			if got != tt.want {
				t.Errorf("GetSecret(%q) = %q, want %q", tt.key, got, tt.want)
			}
		})
	}
}

func TestDecodeExternalStrictNetwork(t *testing.T) {
	config, err := DecodeExternal([]byte(`
network:
  address: 100.64.0.42/20
  gateway: 100.64.0.1
secrets:
  METRICS_API_KEY: metrics-secret
metadata:
  cpu: amd
  operator-label: retained
operator-extension:
  retained: true
`))
	if err != nil {
		t.Fatal(err)
	}
	if config.Network == nil ||
		config.Network.Address != "100.64.0.42/20" ||
		config.Network.Gateway != "100.64.0.1" {
		t.Fatalf("unexpected network config: %+v", config.Network)
	}
	if config.Metadata.CPU != "amd" {
		t.Fatalf("metadata CPU = %q", config.Metadata.CPU)
	}
	if config.Metadata.Extra["operator-label"].Value != "retained" {
		t.Fatalf("operator metadata not retained: %+v", config.Metadata.Extra)
	}
	if config.MetricsAPIKey != "metrics-secret" {
		t.Fatalf("MetricsAPIKey = %q", config.MetricsAPIKey)
	}
	if _, ok := config.Extra["operator-extension"]; !ok {
		t.Fatal("operator-owned top-level extension was not retained")
	}
}

func TestDecodeExternalRejectsUnknownNetworkField(t *testing.T) {
	_, err := DecodeExternal([]byte(`
network:
  address: 100.64.0.42/20
  gateway: 100.64.0.1
  unexpected: true
`))
	if err == nil {
		t.Fatal("DecodeExternal accepted an unknown network field")
	}
}

func TestDecodeExternalRejectsMultipleDocuments(t *testing.T) {
	if _, err := DecodeExternal([]byte("{}\n---\n{}\n")); err == nil {
		t.Fatal("DecodeExternal accepted multiple YAML documents")
	}
}
