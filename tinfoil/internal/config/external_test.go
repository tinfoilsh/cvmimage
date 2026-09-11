package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDecodeExternalConfigRequiresStrictNetwork(t *testing.T) {
	valid := []byte(`
network:
  address: 100.64.0.42/20
  gateway: 100.64.0.1
secrets:
  API_KEY: secret
`)
	if _, err := decodeBootExternal(valid); err != nil {
		t.Fatalf("valid external config rejected: %v", err)
	}

	unknown := strings.Replace(string(valid), "  gateway:", "  unexpected: true\n  gateway:", 1)
	if _, err := decodeBootExternal([]byte(unknown)); err == nil {
		t.Fatal("decodeBootExternal accepted an unknown network field")
	}
	obsolete := strings.Replace(string(valid), "  address:", "  version: 1\n  address:", 1)
	if _, err := decodeBootExternal([]byte(obsolete)); err == nil {
		t.Fatal("decodeBootExternal accepted the obsolete versioned schema")
	}
	for name, document := range map[string]string{
		"missing": "secrets: {}\n",
		"null":    "network: null\n",
		"empty":   "network: {}\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeBootExternal([]byte(document)); err == nil {
				t.Fatalf("decodeBootExternal accepted %s network", name)
			}
		})
	}
}

func TestLoadExternalReturnsOriginalPayload(t *testing.T) {
	source := []byte("# preserve host metadata bytes\nnetwork:\n  address: 100.64.0.42/20\n  gateway: 100.64.0.1\n")
	path := filepath.Join(t.TempDir(), "external")
	if err := os.WriteFile(path, append(source, 0, 0), 0600); err != nil {
		t.Fatal(err)
	}
	config, data, err := LoadExternal(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != string(source) || config.Network.Address != "100.64.0.42/20" {
		t.Fatal("external payload changed during loading")
	}
}
