package config

import (
	"reflect"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestConfigDefaults(t *testing.T) {
	config := newConfig()
	tests := []struct {
		name string
		got  any
		want any
	}{
		{"upstream port", config.UpstreamPort, 0},
		{"upstream container", config.UpstreamContainer, ""},
		{"paths", config.Paths, []string(nil)},
		{"origin domains", config.OriginDomains, []string(nil)},
		{"TLS mode", config.TLSMode, "cert-proxy"},
		{"TLS environment", config.TLSEnv, "production"},
		{"TLS challenge mode", config.TLSChallengeMode, "dns"},
		{"TLS wildcard", config.TLSWildcard, false},
		{"TLS own SAN domain", config.TLSOwnSANDomain, false},
		{"control plane", config.ControlPlane, "https://api.tinfoil.sh"},
		{"authenticated", config.Authenticated, false},
		{"authenticated endpoints", config.AuthenticatedEndpoints, (*[]string)(nil)},
		{"rate limit", config.RateLimit, float64(0)},
		{"rate burst", config.RateBurst, 0},
		{"email", config.Email, "tls@tinfoil.sh"},
		{"publish attestation", config.PublishAttestation, true},
		{"dummy attestation", config.DummyAttestation, false},
		{"expected GPUs", config.ExpectedGPUs, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !reflect.DeepEqual(tt.got, tt.want) {
				t.Errorf("default = %#v, want %#v", tt.got, tt.want)
			}
		})
	}
}

func TestExternalConfigDefaults(t *testing.T) {
	config := newExternalConfig()
	tests := []struct {
		name string
		got  any
		want any
	}{
		{"metrics API key", config.MetricsAPIKey, ""},
		{"ACPI API key", config.ACPIAPIKey, ""},
		{"environment", config.Env, map[string]string(nil)},
		{"secrets", config.Secrets, map[string]string(nil)},
		{"metadata", config.Metadata, Metadata{}},
		{"vault token", config.VaultToken, ""},
		{"network", config.Network, (*ExternalNetworkConfig)(nil)},
		{"extra", config.Extra, map[string]yaml.Node(nil)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !reflect.DeepEqual(tt.got, tt.want) {
				t.Errorf("default = %#v, want %#v", tt.got, tt.want)
			}
		})
	}
}

func TestDecodeExternalDefaults(t *testing.T) {
	config, err := DecodeExternal([]byte("{}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if want := newExternalConfig(); !reflect.DeepEqual(*config, want) {
		t.Errorf("DecodeExternal() = %#v, want %#v", *config, want)
	}
}

func TestDecodeConfigDefaultsAndExplicitOverrides(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want Config
	}{
		{
			name: "defaults",
			yaml: "upstream-port: 8080\n",
			want: func() Config {
				config := newConfig()
				config.UpstreamPort = 8080
				return config
			}(),
		},
		{
			name: "explicit values including zero and false",
			yaml: `
upstream-port: 8080
upstream-container: ""
paths: []
origins: []
tls-mode: self-signed
tls-env: staging
tls-challenge: http
tls-wildcard: false
tls-own-san-domain: false
control-plane: ""
authenticated: false
authenticated-endpoints: []
rate-limit: 0
rate-burst: 0
email: ""
publish-attestation: false
dummy-attestation: false
expected-gpus: 0
`,
			want: Config{
				UpstreamPort:           8080,
				Paths:                  []string{},
				OriginDomains:          []string{},
				TLSMode:                "self-signed",
				TLSEnv:                 "staging",
				TLSChallengeMode:       "http",
				AuthenticatedEndpoints: pointerToSlice([]string{}),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node, err := decodeYAMLDocument([]byte(tt.yaml))
			if err != nil {
				t.Fatal(err)
			}
			got, err := Decode(node)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(*got, tt.want) {
				t.Errorf("Decode() = %#v, want %#v", *got, tt.want)
			}
		})
	}
}

func TestDecodeConfigBooleanOverrides(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		get  func(*Config) bool
		want bool
	}{
		{"TLS wildcard true", "tls-wildcard: true\n", func(config *Config) bool { return config.TLSWildcard }, true},
		{"TLS own SAN domain true", "tls-own-san-domain: true\n", func(config *Config) bool { return config.TLSOwnSANDomain }, true},
		{"authenticated true", "authenticated: true\n", func(config *Config) bool { return config.Authenticated }, true},
		{"publish attestation false", "publish-attestation: false\n", func(config *Config) bool { return config.PublishAttestation }, false},
		{"dummy attestation true", "dummy-attestation: true\n", func(config *Config) bool { return config.DummyAttestation }, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node, err := decodeYAMLDocument([]byte("upstream-port: 8080\n" + tt.yaml))
			if err != nil {
				t.Fatal(err)
			}
			config, err := Decode(node)
			if err != nil {
				t.Fatal(err)
			}
			got := tt.get(config)
			if got != tt.want {
				t.Errorf("decoded value = %t, want %t", got, tt.want)
			}
		})
	}
}

func pointerToSlice(value []string) *[]string {
	return &value
}

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
