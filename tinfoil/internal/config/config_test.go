package config

import (
	"encoding/json/jsontext"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestDecodeServiceURLDefaults(t *testing.T) {
	cfg, err := Decode([]byte(`{"upstream-port":8080}`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ControlPlane != "https://api.tinfoil.sh" {
		t.Errorf("ControlPlane default = %q", cfg.ControlPlane)
	}
	if cfg.ATC != "https://atc.tinfoil.sh" {
		t.Errorf("ATC default = %q", cfg.ATC)
	}

	cfg, err = Decode([]byte(`{"upstream-port":8080,"atc":"http://100.64.0.1:8085"}`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ATC != "http://100.64.0.1:8085" {
		t.Errorf("ATC override = %q", cfg.ATC)
	}
}

func TestDecodeReadsOneJSONObject(t *testing.T) {
	for name, data := range map[string]string{
		"missing document": "",
		"null":             "null",
		"array":            `[{"upstream-port":8080}]`,
		"YAML":             "upstream-port: 8080\n",
		"second object":    `{"upstream-port":8080} {}`,
		"repeated member":  `{"upstream-port":8080,"upstream-port":8081}`,
		"unknown member":   `{"upstream-port":8080,"upstream-prot":8081}`,
		"number as text":   `{"upstream-port":"8080"}`,
		"invalid settings": `{"upstream-port":8080,"tls-mode":"plaintext"}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Decode([]byte(data)); err == nil {
				t.Fatalf("Decode accepted %s", name)
			}
		})
	}
}

// The runtime writes the shim settings with Encode and the shim reads them
// with Decode, so every setting has to survive the pair.
func TestShimSettingsRoundTrip(t *testing.T) {
	endpoints := []string{"/v1/chat/completions"}
	settings := &Config{
		UpstreamPort: 8080, UpstreamContainer: "app", Paths: []string{"/v1/*"}, OriginDomains: []string{"https://app.example.com"},
		TLSMode: "acme", TLSEnv: "staging", TLSChallengeMode: "dns", TLSWildcard: true, TLSOwnSANDomain: true,
		ControlPlane: "https://api.example.com", ATC: "http://100.64.0.1:8085", Authenticated: true, AuthenticatedEndpoints: &endpoints,
		RateLimit: 2.5, RateBurst: 7, DrainConnections: true, DrainTimeout: 90*time.Second + time.Nanosecond,
		Email: "ops@example.com", PublishAttestation: true, DummyAttestation: true, ExpectedGPUs: 2,
	}
	value := reflect.ValueOf(*settings)
	for index := range value.NumField() {
		if value.Field(index).IsZero() {
			t.Fatalf("the fixture leaves %s unset, so its round trip is not tested", value.Type().Field(index).Name)
		}
	}
	data, err := Encode(settings)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoded, settings) {
		t.Fatalf("settings after the round trip = %+v, want %+v\nfile: %s", decoded, settings, data)
	}

	// A setting turned off must not come back as its default, nor an unset
	// list of endpoints as an empty one.
	settings = &Config{UpstreamPort: 8080, TLSMode: "self-signed", TLSEnv: "production", TLSChallengeMode: "tls", DrainTimeout: time.Minute}
	if data, err = Encode(settings); err != nil {
		t.Fatal(err)
	}
	if decoded, err = Decode(data); err != nil {
		t.Fatal(err)
	}
	if decoded.PublishAttestation || decoded.AuthenticatedEndpoints != nil || len(decoded.Paths) != 0 || decoded.Email != "" || decoded.ControlPlane != "" {
		t.Fatalf("unset settings after the round trip = %+v\nfile: %s", decoded, data)
	}
	empty := []string{}
	settings.AuthenticatedEndpoints = &empty
	if data, err = Encode(settings); err != nil {
		t.Fatal(err)
	}
	if decoded, err = Decode(data); err != nil {
		t.Fatal(err)
	}
	if decoded.AuthenticatedEndpoints == nil || len(*decoded.AuthenticatedEndpoints) != 0 {
		t.Fatalf("empty endpoint list after the round trip = %v\nfile: %s", decoded.AuthenticatedEndpoints, data)
	}
}

// Load is how the shim reads the settings the runtime derived for it and the
// external config the host supplied.
func TestLoadReadsShimSettingsAndExternalConfig(t *testing.T) {
	directory := t.TempDir()
	settingsPath, externalPath := filepath.Join(directory, "shim.json"), filepath.Join(directory, "external-config.json")
	settings, err := Encode(&Config{UpstreamPort: 8080, UpstreamContainer: "app", TLSMode: "self-signed", TLSEnv: "production", TLSChallengeMode: "tls", DrainTimeout: 90 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	external, err := os.ReadFile(externalConfigGolden)
	if err != nil {
		t.Fatal(err)
	}
	for path, data := range map[string][]byte{settingsPath: settings, externalPath: external} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	config, externalConfig, err := Load(settingsPath, externalPath)
	if err != nil {
		t.Fatal(err)
	}
	if config.UpstreamContainer != "app" || config.DrainTimeout != 90*time.Second || externalConfig.Env["DOMAIN"] != "llm.inference.example.com" {
		t.Fatalf("loaded settings = %+v, external config = %+v", config, externalConfig)
	}
	if _, _, err := Load(externalPath, externalPath); err == nil {
		t.Fatal("Load read an external config as shim settings")
	}
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

// externalConfigGolden is the external config of one launch as tinfoild
// writes it for a guest that reads JSON. tinfoild keeps the same bytes at
// admin/testdata/external-config.json, where a test of its writer produces
// them, so a change to one copy is a change to both.
const externalConfigGolden = "testdata/external-config.json"

func TestDecodeExternalReadsHostGolden(t *testing.T) {
	data, err := os.ReadFile(externalConfigGolden)
	if err != nil {
		t.Fatal(err)
	}
	config, err := DecodeExternal(data)
	if err != nil {
		t.Fatal(err)
	}
	want := &ExternalConfig{
		MetricsAPIKey: "fixture-metrics-key",
		Env: map[string]string{
			"DOMAIN": "llm.inference.example.com", "ENABLE_TRACING": "true", "GREETING": "grüß dich", "LOG_LEVEL": "info", "PORT": "8080",
		},
		Secrets: map[string]string{
			"API_TOKEN":           `fixture <token> & "quotes"`,
			"CERT_AUTH_TOKEN":     "fixture-cert-auth-token",
			"METRICS_API_KEY":     "fixture-metrics-key",
			"SSH_AUTHORIZED_KEYS": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixtureKeyOne ops@example.com\nssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixtureKeyTwo oncall@example.com\n",
		},
		Metadata: Metadata{
			ID: "k3v9x2m7q4w8z1b6", Domain: "llm.inference.example.com", Image: "example/llm@v1.4.0", CPU: "amd", GPU: "1xh200",
			Repo: "example/llm", Tag: "v1.4.0", Digest: strings.Repeat("c", 64),
			Extra: map[string]jsontext.Value{
				"profile": jsontext.Value(`"https://tinfoil.sh/predicate/attestation-collaterals/v3"`),
				"team":    jsontext.Value(`"inference"`),
			},
		},
		Network:       &ExternalNetworkConfig{Address: "100.64.0.42/20", Gateway: "100.64.0.1"},
		ShutdownToken: strings.Repeat("0123456789abcdef", 4),
		Extra: map[string]jsontext.Value{
			"operator": jsontext.Value(`{"regions":["eu-west","us-east"],"ticket":4721}`),
		},
	}
	if !reflect.DeepEqual(config, want) {
		t.Fatalf("golden external config = %+v\nwant %+v", config, want)
	}
}

func TestDecodeExternalStrictNetwork(t *testing.T) {
	config, err := DecodeExternal([]byte(`{
  "network": {"address": "100.64.0.42/20", "gateway": "100.64.0.1"},
  "secrets": {"METRICS_API_KEY": "metrics-secret"},
  "metadata": {"cpu": "amd", "operator-label": "retained"},
  "operator-extension": {"retained": true}
}`))
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
	if string(config.Metadata.Extra["operator-label"]) != `"retained"` {
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
	_, err := DecodeExternal([]byte(`{"network": {"address": "100.64.0.42/20", "gateway": "100.64.0.1", "unexpected": true}}`))
	if err == nil {
		t.Fatal("DecodeExternal accepted an unknown network field")
	}
}

func TestDecodeExternalReadsOneJSONObject(t *testing.T) {
	for name, data := range map[string]string{
		"empty":                    "",
		"null":                     "null",
		"array":                    "[]",
		"second object":            "{} {}",
		"YAML documents":           "{}\n---\n{}\n",
		"YAML":                     "env:\n  PORT: \"8080\"\n",
		"repeated member":          `{"env":{"A":"1"},"env":{"A":"2"}}`,
		"repeated environment key": `{"env":{"A":"1","A":"2"}}`,
		"number in the env":        `{"env":{"PORT":8080}}`,
		"number as metadata":       `{"metadata":{"id":7}}`,
		"env that is a list":       `{"env":["PORT=8080"]}`,
		"text that is not UTF-8":   "{\"env\":{\"A\":\"\xff\"}}",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeExternal([]byte(data)); err == nil {
				t.Fatalf("DecodeExternal accepted %s", name)
			}
		})
	}
	// A member the document leaves null is one it leaves out.
	config, err := DecodeExternal([]byte(`{"env":null,"secrets":{"KEY":null},"metadata":null,"network":null,"shutdown_token":null}`))
	if err != nil {
		t.Fatal(err)
	}
	if config.Network != nil || config.Env != nil || config.Secrets["KEY"] != "" || config.ShutdownToken != "" {
		t.Fatalf("null members = %+v", config)
	}
	// Member names match exactly, so this one is the operator's.
	config, err = DecodeExternal([]byte(`{"Network":{"unexpected":true}}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, kept := config.Extra["Network"]; !kept || config.Network != nil {
		t.Fatalf("member named by another case = %+v", config)
	}
}
