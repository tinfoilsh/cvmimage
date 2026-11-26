package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/json/jsontext"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	shimconfig "tinfoil/internal/config"
	"tinfoil/internal/configtest"
	"tinfoil/internal/runtimeconfig"
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
		Address: "100.64.0.42/20",
		Gateway: "100.64.0.1",
	}
	if err := validateExternalNetwork(&valid); err != nil {
		t.Fatalf("valid network rejected: %v", err)
	}

	for name, mutate := range map[string]func(*shimconfig.ExternalNetworkConfig){
		"IPv6": func(c *shimconfig.ExternalNetworkConfig) {
			c.Address, c.Gateway = "2001:db8::2/64", "2001:db8::1"
		},
		"mapped IPv6": func(c *shimconfig.ExternalNetworkConfig) {
			c.Address, c.Gateway = "::ffff:100.64.0.42/120", "::ffff:100.64.0.1"
		},
		"missing prefix": func(c *shimconfig.ExternalNetworkConfig) {
			c.Address = "100.64.0.42"
		},
		"point-to-point prefix": func(c *shimconfig.ExternalNetworkConfig) {
			c.Address, c.Gateway = "192.0.2.0/31", "192.0.2.1"
		},
		"host prefix": func(c *shimconfig.ExternalNetworkConfig) {
			c.Address, c.Gateway = "192.0.2.1/32", "192.0.2.1"
		},
		"alias gateway": func(c *shimconfig.ExternalNetworkConfig) {
			c.Address, c.Gateway = "10.254.0.2/24", "10.254.0.1"
		},
		"alias guest": func(c *shimconfig.ExternalNetworkConfig) {
			c.Address, c.Gateway = "10.254.0.254/30", "10.254.0.253"
		},
		"alias in subnet": func(c *shimconfig.ExternalNetworkConfig) {
			c.Address, c.Gateway = "10.254.1.2/23", "10.254.1.1"
		},
		"subnet within upper alias range": func(c *shimconfig.ExternalNetworkConfig) {
			c.Address, c.Gateway = "10.254.0.130/25", "10.254.0.129"
		},
		"alias in broad subnet": func(c *shimconfig.ExternalNetworkConfig) {
			c.Address, c.Gateway = "100.64.0.2/0", "100.64.0.1"
		},
		"subnet":    func(c *shimconfig.ExternalNetworkConfig) { c.Gateway = "192.0.2.1" },
		"network":   func(c *shimconfig.ExternalNetworkConfig) { c.Address = "100.64.0.0/20" },
		"broadcast": func(c *shimconfig.ExternalNetworkConfig) { c.Address = "100.64.15.255/20" },
		"gateway":   func(c *shimconfig.ExternalNetworkConfig) { c.Address = "100.64.0.1/20" },
		"gateway network": func(c *shimconfig.ExternalNetworkConfig) {
			c.Gateway = "100.64.0.0"
		},
		"gateway broadcast": func(c *shimconfig.ExternalNetworkConfig) {
			c.Gateway = "100.64.15.255"
		},
	} {
		t.Run(name, func(t *testing.T) {
			config := valid
			mutate(&config)
			if err := validateExternalNetwork(&config); err == nil {
				t.Fatalf("invalid network accepted: %+v", config)
			}
		})
	}
	if err := validateExternalNetwork(nil); err == nil {
		t.Fatal("missing external network accepted")
	}
	for _, address := range []string{"10.253.255.2/24", "10.254.1.2/24"} {
		config := shimconfig.ExternalNetworkConfig{Address: address, Gateway: strings.Replace(address, ".2/24", ".1", 1)}
		if err := validateExternalNetwork(&config); err != nil {
			t.Fatalf("non-overlapping neighboring subnet rejected: %v", err)
		}
	}
}

func TestDecodeExternalConfigRequiresStrictNetwork(t *testing.T) {
	const valid = `{"network":{"address":"100.64.0.42/20","gateway":"100.64.0.1"},"secrets":{"API_KEY":"secret"}}`
	if _, err := decodeExternalConfig([]byte(valid)); err != nil {
		t.Fatalf("valid external config rejected: %v", err)
	}

	unknown := strings.Replace(valid, `"gateway":`, `"unexpected":true,"gateway":`, 1)
	if _, err := decodeExternalConfig([]byte(unknown)); err == nil {
		t.Fatal("decodeExternalConfig accepted an unknown network field")
	}
	obsolete := strings.Replace(valid, `"address":`, `"version":1,"address":`, 1)
	if _, err := decodeExternalConfig([]byte(obsolete)); err == nil {
		t.Fatal("decodeExternalConfig accepted the obsolete versioned schema")
	}
	for name, document := range map[string]string{
		"missing": `{"secrets":{}}`,
		"null":    `{"network":null}`,
		"empty":   `{"network":{}}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeExternalConfig([]byte(document)); err == nil {
				t.Fatalf("decodeExternalConfig accepted %s network", name)
			}
		})
	}
}

// The host attaches the external config as a raw disk that holds the JSON
// document and nothing else; the device pads it with NUL bytes to a whole
// sector. The document is the one tinfoild's writer is tested to produce.
func TestExternalConfigDiskCarriesHostDocument(t *testing.T) {
	const sectorBytes = 512
	document, err := os.ReadFile(filepath.Join("..", "..", "internal", "config", "testdata", "external-config.json"))
	if err != nil {
		t.Fatal(err)
	}
	disk := filepath.Join(t.TempDir(), "external-config-disk")
	padding := make([]byte, sectorBytes-len(document)%sectorBytes)
	if err := os.WriteFile(disk, append(bytes.Clone(document), padding...), 0o600); err != nil {
		t.Fatal(err)
	}
	payload, err := readDiskPayload(disk, maxDiskPayloadBytes)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(payload, document) {
		t.Fatalf("disk payload = %q, want the document", payload)
	}
	config, err := decodeExternalConfig(payload)
	if err != nil {
		t.Fatal(err)
	}
	if config.Network.Address != "100.64.0.42/20" || config.Env["PORT"] != "8080" || config.ShutdownToken == "" {
		t.Fatalf("external config from disk = %+v", config)
	}

	// A guest that reads JSON is never told the format and does not guess:
	// the YAML that earlier images take is refused.
	yamlDocument := "network:\n  address: 100.64.0.42/20\n  gateway: 100.64.0.1\nenv:\n  PORT: \"8080\"\n"
	if _, err := decodeExternalConfig([]byte(yamlDocument)); err == nil {
		t.Fatal("decodeExternalConfig accepted a YAML document")
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

// configDiskPadding is how far past a config the host pads its disk here.
const configDiskPadding = 512

func writeConfigDisk(t *testing.T, config []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config-disk")
	if err := os.WriteFile(path, append(bytes.Clone(config), make([]byte, configDiskPadding)...), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func launchHashOf(config []byte) func() (string, error) {
	return func() (string, error) {
		digest := sha256.Sum256(config)
		return hex.EncodeToString(digest[:]), nil
	}
}

func TestLoadMeasuredConfigBootsJSON(t *testing.T) {
	data := configtest.JSON(t, configtest.Workload)
	installPath := filepath.Join(t.TempDir(), "config.json")
	config, hash, err := loadMeasuredConfig(writeConfigDisk(t, data), installPath, launchHashOf(data), false, false)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	if hash != hex.EncodeToString(digest[:]) {
		t.Fatalf("config hash = %s, want the SHA-256 of the config bytes", hash)
	}
	installed, err := os.ReadFile(installPath)
	if err != nil || !bytes.Equal(installed, data) {
		t.Fatalf("installed config = %q, %v; want the config bytes", installed, err)
	}
	if config.CVMVersion != configtest.CVMVersion || config.CPUs != 4 || config.Memory != 8192 || !config.Security.IncludeConfigInAttestation {
		t.Fatalf("config = %#v", config)
	}
	shim := config.ShimCfg
	if shim.UpstreamPort != 8080 || shim.UpstreamContainer != "app" || shim.RateLimit != 2.5 || shim.DrainTimeout != 90*time.Second || shim.DummyAttestation {
		t.Fatalf("shim config = %#v", shim)
	}
	if len(config.Containers) != 2 || config.Containers[1].Name != "sidecar" || config.Networks["app"].Egress != "closed" {
		t.Fatalf("containers = %#v, networks = %#v", config.Containers, config.Networks)
	}
	app := config.Containers[0]
	if app.CPUs != 1.5 || app.Restart != "always" || app.Provenance.GitHub.RepositoryID != 123456789 ||
		!reflect.DeepEqual(app.Env, []any{"HF_TOKEN", map[string]any{"PORT": "8080"}}) ||
		!reflect.DeepEqual(app.Ports, []string{"2300:25565", "2301:8080"}) {
		t.Fatalf("container = %#v", app)
	}
}

func TestLoadMeasuredConfigAcceptsTheMeasuredDebugToolbox(t *testing.T) {
	workload := configtest.JSON(t, configtest.Workload)
	var document map[string]any
	if err := json.Unmarshal(workload, &document); err != nil {
		t.Fatal(err)
	}
	document["containers"] = append(document["containers"].([]any), map[string]any{
		"name":    runtimeconfig.ReservedDebugContainerName,
		"image":   "ghcr.io/tinfoilsh/tinfoil-debug-toolbox@sha256:" + strings.Repeat("a", 64),
		"volumes": []any{runtimeconfig.DebugDockerSocketBind, runtimeconfig.DebugManagerSocketBind},
	})
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	withToolbox := jsontext.Value(encoded)
	if err := withToolbox.Canonicalize(); err != nil {
		t.Fatal(err)
	}
	installPath := filepath.Join(t.TempDir(), "config.json")
	config, _, err := loadMeasuredConfig(writeConfigDisk(t, withToolbox), installPath, launchHashOf(withToolbox), false, false)
	if err != nil || !runtimeconfig.HoldsDebugToolbox(config) {
		t.Fatalf("config = %#v, err = %v; want the measured toolbox accepted", config, err)
	}
	if _, _, err := loadMeasuredConfig(writeConfigDisk(t, withToolbox), installPath, launchHashOf(workload), false, false); err == nil {
		t.Fatal("a toolbox the launch did not measure was accepted")
	}
}

func TestLoadMeasuredConfigNeedsLaunchHashUnlessNonCC(t *testing.T) {
	data := configtest.JSON(t, configtest.Workload)
	unreadable := func() (string, error) { return "", errors.New("no attestation device") }
	installPath := filepath.Join(t.TempDir(), "config.json")
	if _, _, err := loadMeasuredConfig(writeConfigDisk(t, data), installPath, unreadable, false, false); err == nil {
		t.Fatal("config accepted without a launch hash")
	}
	config, _, err := loadMeasuredConfig(writeConfigDisk(t, data), installPath, unreadable, true, false)
	if err != nil || !config.ShimCfg.DummyAttestation {
		t.Fatalf("non-CC config = %#v, %v; want dummy attestation", config, err)
	}
}

func TestLoadMeasuredConfigHashesExactBytes(t *testing.T) {
	data := configtest.JSON(t, configtest.Workload)
	for name, launched := range map[string][]byte{
		"YAML source":      []byte(configtest.Workload),
		"trailing newline": append(bytes.Clone(data), '\n'),
	} {
		t.Run(name, func(t *testing.T) {
			installPath := filepath.Join(t.TempDir(), "config.json")
			_, _, err := loadMeasuredConfig(writeConfigDisk(t, data), installPath, launchHashOf(launched), false, false)
			if err == nil || !strings.Contains(err.Error(), "config hash mismatch") {
				t.Fatalf("error = %v, want a config hash mismatch", err)
			}
			if _, err := os.Stat(installPath); !os.IsNotExist(err) {
				t.Fatalf("unverified config was installed: %v", err)
			}
		})
	}
}

func TestLoadMeasuredConfigTakesOnlyJSON(t *testing.T) {
	earlier := strings.Replace(configtest.Workload, configtest.CVMVersion, configtest.YAMLCVMVersion, 1)
	var indented bytes.Buffer
	if err := json.Indent(&indented, configtest.JSON(t, configtest.Workload), "", "  "); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		data []byte
		want string
	}{
		{name: "YAML", data: []byte(configtest.Workload), want: "take a JSON config"},
		{name: "YAML for an earlier runtime", data: []byte(earlier), want: "take a JSON config"},
		{name: "JSON with extra whitespace", data: indented.Bytes(), want: "not in canonical form"},
		{name: "JSON with a trailing newline", data: append(configtest.JSON(t, configtest.Workload), '\n'), want: "not in canonical form"},
	} {
		t.Run(test.name, func(t *testing.T) {
			installPath := filepath.Join(t.TempDir(), "config.json")
			_, _, err := loadMeasuredConfig(writeConfigDisk(t, test.data), installPath, launchHashOf(test.data), false, false)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want substring %q", err, test.want)
			}
		})
	}
}
