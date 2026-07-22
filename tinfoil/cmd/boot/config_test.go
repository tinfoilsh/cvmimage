package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	shimconfig "tinfoil/internal/config"
)

func TestValidateGPUCount(t *testing.T) {
	for count := range maxGPUCount + 1 {
		if err := validateGPUCount(count); err != nil {
			t.Fatalf("expected GPU count %d to be valid: %v", count, err)
		}
	}

	for _, count := range []int{-1, 9} {
		if err := validateGPUCount(count); err == nil {
			t.Fatalf("expected GPU count %d to be invalid", count)
		}
	}
}

func TestValidateModelCount(t *testing.T) {
	for _, count := range []int{0, 1, 24} {
		if err := validateModelCount(count); err != nil {
			t.Fatalf("model count %d rejected: %v", count, err)
		}
	}
	for _, count := range []int{-1, 25} {
		if err := validateModelCount(count); err == nil {
			t.Fatalf("model count %d accepted", count)
		}
	}
}

func TestValidateExternalNetwork(t *testing.T) {
	valid := shimconfig.ExternalNetworkConfig{
		Version: 1,
		Address: "100.64.0.42/20",
		Gateway: "100.64.0.1",
	}
	if err := validateExternalNetwork(&valid); err != nil {
		t.Fatalf("valid network rejected: %v", err)
	}

	for name, config := range map[string]shimconfig.ExternalNetworkConfig{
		"version zero": {Version: 0, Address: valid.Address, Gateway: valid.Gateway},
		"version two":  {Version: 2, Address: valid.Address, Gateway: valid.Gateway},
		"version negative": {
			Version: -1, Address: valid.Address, Gateway: valid.Gateway,
		},
		"IPv6": {Version: 1, Address: "2001:db8::2/64", Gateway: "2001:db8::1"},
		"mapped IPv6": {
			Version: 1, Address: "::ffff:100.64.0.42/120", Gateway: "::ffff:100.64.0.1",
		},
		"missing prefix": {Version: 1, Address: "100.64.0.42", Gateway: valid.Gateway},
		"subnet":         {Version: 1, Address: valid.Address, Gateway: "192.0.2.1"},
		"network":        {Version: 1, Address: "100.64.0.0/20", Gateway: valid.Gateway},
		"broadcast":      {Version: 1, Address: "100.64.15.255/20", Gateway: valid.Gateway},
		"gateway":        {Version: 1, Address: "100.64.0.1/20", Gateway: valid.Gateway},
		"gateway network": {
			Version: 1, Address: valid.Address, Gateway: "100.64.0.0",
		},
		"gateway broadcast": {
			Version: 1, Address: valid.Address, Gateway: "100.64.15.255",
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateExternalNetwork(&config); err == nil {
				t.Fatalf("invalid network accepted: %+v", config)
			}
		})
	}
	if err := validateExternalNetwork(nil); err == nil {
		t.Fatal("missing external network accepted")
	}
}

func TestDecodeExternalConfigRequiresStrictNetwork(t *testing.T) {
	valid := []byte(`
network:
  version: 1
  address: 10.0.2.15/24
  gateway: 10.0.2.2
secrets:
  API_KEY: secret
`)
	if _, err := decodeExternalConfig(valid); err != nil {
		t.Fatalf("valid external config rejected: %v", err)
	}

	unknown := strings.Replace(string(valid), "  gateway:", "  dns: 10.0.2.3\n  gateway:", 1)
	if _, err := decodeExternalConfig([]byte(unknown)); err == nil {
		t.Fatal("decodeExternalConfig accepted an unknown network field")
	}
	for name, document := range map[string]string{
		"missing": "secrets: {}\n",
		"null":    "network: null\n",
		"empty":   "network: {}\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeExternalConfig([]byte(document)); err == nil {
				t.Fatalf("decodeExternalConfig accepted %s network", name)
			}
		})
	}
}

func TestReadDiskPayloadIsBoundedAndRequiresZeroPadding(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	if err := os.WriteFile(path, append([]byte("gpus: 0\n"), make([]byte, 32)...), 0644); err != nil {
		t.Fatal(err)
	}
	data, err := readDiskPayload(path, 16)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "gpus: 0\n" {
		t.Fatalf("payload = %q", data)
	}

	if err := os.WriteFile(path, []byte("valid\x00hidden"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readDiskPayload(path, 16); err == nil {
		t.Fatal("readDiskPayload accepted data after NUL padding")
	}

	if err := os.WriteFile(path, []byte(strings.Repeat("x", 17)), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readDiskPayload(path, 16); err == nil {
		t.Fatal("readDiskPayload accepted an oversized payload")
	}
}
