package runtimeconfig

import (
	"encoding/json"
	"encoding/json/jsontext"
	"fmt"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"tinfoil/internal/configtest"
)

// asJSON writes a YAML test config as the JSON document with the same
// members. It does not validate the config, so one that Decode must refuse
// can be written too.
func asJSON(t *testing.T, text string) []byte {
	t.Helper()
	var document any
	if err := yaml.Unmarshal([]byte(text), &document); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	canonical := jsontext.Value(encoded)
	if err := canonical.Canonicalize(); err != nil {
		t.Fatal(err)
	}
	return canonical
}

func TestDecodeRejectsUnknownHealthcheckField(t *testing.T) {
	_, err := Decode(asJSON(t, versionLine+`
shim: {}
containers:
  - name: app
    image: example.com/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    healthcheck:
      test: [CMD, ok]
      retrise: 3
`), false)
	if err == nil || !strings.Contains(err.Error(), `unknown object member name "retrise"`) {
		t.Fatalf("Decode error = %v", err)
	}
}

const versionLine = "cvm-version: " + configtest.CVMVersion

const validConfig = `
` + versionLine + `
shim:
  upstream-port: 8080
networks:
  app:
    egress: closed
containers:
  - name: app
    image: example.com/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    networks: [app]
`

func TestDecodeValidatesRuntimeConfig(t *testing.T) {
	for _, test := range []struct {
		name  string
		yaml  string
		debug bool
		want  string
	}{
		{name: "valid", yaml: validConfig},
		{name: "keyserver URL", yaml: validConfig + "keyserver-url: https://keys.example.com\n"},
		{name: "obsolete vault URL", yaml: validConfig + "vault-url: https://keys.example.com\n", want: `unknown object member name "vault-url"`},
		{name: "unknown field", yaml: validConfig + "unknown: true\n", want: `unknown object member name "unknown"`},
		{name: "unknown container field", yaml: strings.Replace(validConfig, "networks: [app]", "networks: [app]\n    typo: true", 1), want: `unknown object member name "typo"`},
		{name: "duplicate container", yaml: strings.Replace(validConfig, "containers:\n", "containers:\n  - name: app\n    image: example.com/duplicate@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n", 1), want: "duplicates"},
		{name: "mutable image", yaml: strings.Replace(validConfig, "example.com/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "example.com/app:latest", 1), want: "immutable digest"},
		{name: "debug mutable image", debug: true, yaml: strings.Replace(validConfig, "example.com/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "example.com/app:latest", 1), want: "immutable digest"},
		{name: "undeclared network", yaml: strings.Replace(validConfig, "networks: [app]", "networks: [missing]", 1), want: "not declared"},
		{name: "production docker socket", yaml: strings.Replace(validConfig, "networks: [app]", "networks: [app]\n    volumes: [/run/docker.sock:/var/run/docker.sock]", 1), want: "must use a named volume source"},
		{name: "declared volume attached", yaml: strings.Replace(validConfig, "networks: [app]", "networks: [app]\n    persistent_volumes: [workspace:/workspace]", 1) + "volumes:\n  - name: workspace\n    exec: true\n"},
		{name: "undeclared volume attached", yaml: strings.Replace(validConfig, "networks: [app]", "networks: [app]\n    persistent_volumes: [workspace:/workspace]", 1), want: "must name a volume declared in volumes"},
		{name: "debug toolbox socket", debug: true, yaml: strings.Replace(validConfig, "name: app\n    image", fmt.Sprintf("name: %s\n    volumes: [/run/docker.sock:/var/run/docker.sock]\n    image", ReservedDebugContainerName), 1)},
		{name: "debug toolbox capability", debug: true, yaml: strings.Replace(validConfig, "name: app\n    image", fmt.Sprintf("name: %s\n    cap_add: [SETGID]\n    image", ReservedDebugContainerName), 1), want: "capability"},
		{name: "host ipc", yaml: strings.Replace(validConfig, "networks: [app]", "networks: [app]\n    ipc: host", 1), want: "ipc must be private or none"},
		{name: "host pid", yaml: strings.Replace(validConfig, "networks: [app]", "networks: [app]\n    pid: host", 1), want: "pid is unsupported"},
		{name: "raw device", yaml: strings.Replace(validConfig, "networks: [app]", "networks: [app]\n    devices: [/dev/kvm]", 1), want: "devices is unsupported"},
		{name: "implicit runtime alias", yaml: strings.Replace(validConfig, "networks: [app]", "networks: [app]\n    runtime: attacker.runc.v2", 1), want: "runtime"},
		{name: "nvidia runtime without selection", yaml: strings.Replace(validConfig, "networks: [app]", "networks: [app]\n    runtime: nvidia", 1), want: "explicit gpus selection"},
		{name: "gpu selection without runtime", yaml: strings.Replace(validConfig, "networks: [app]", "networks: [app]\n    gpus: all", 1), want: "declares no GPUs"},
		{name: "valid top-level gpu count", yaml: strings.Replace(validConfig, versionLine, versionLine+"\ngpus: 2", 1) + "\n", want: ""},
		{name: "unsupported capability", yaml: strings.Replace(validConfig, "networks: [app]", "networks: [app]\n    cap_add: [SETUID]", 1), want: "capability"},
		{name: "clock capability", yaml: strings.Replace(validConfig, "networks: [app]", "networks: [app]\n    cap_add: [SYS_TIME]", 1), want: "capability"},
		{name: "model key exposed to container", yaml: strings.Replace(validConfig, "networks: [app]", "networks: [app]\n    secrets: [MODEL_KEY]", 1) + "\nmodels:\n  - name: private\n    key-secret: MODEL_KEY\n", want: "exposes models[0].key-secret"},
		{name: "invalid allowlist", yaml: strings.Replace(validConfig, "egress: closed", "egress: allowlist\n    allow: ['*.example.com']", 1), want: "wildcards"},
		{name: "published port", yaml: strings.Replace(validConfig, "networks: [app]", "networks: [app]\n    ports: ['2022:22']", 1)},
		{name: "malformed port", yaml: strings.Replace(validConfig, "networks: [app]", "networks: [app]\n    ports: ['70000:22']", 1), want: `must be "<host>:<container>"`},
		{name: "reserved host port", yaml: strings.Replace(validConfig, "networks: [app]", "networks: [app]\n    ports: ['443:22']", 1), want: "reserved for the shim"},
		{name: "port without network", yaml: strings.Replace(validConfig, "networks: [app]", "ports: ['2022:22']", 1), want: "requires an attached network"},
		{name: "duplicate host port", yaml: strings.Replace(validConfig, "containers:\n", "containers:\n  - name: other\n    image: example.com/other@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n    networks: [app]\n    ports: ['2022:22']\n", 1) + "    ports: ['2022:2222']\n", want: `already published by "other"`},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := Decode(asJSON(t, test.yaml), test.debug)
			if test.want == "" && err != nil {
				t.Fatal(err)
			}
			if test.want != "" && (err == nil || !strings.Contains(err.Error(), test.want)) {
				t.Fatalf("error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestDecodeValidatesModelAccess(t *testing.T) {
	const ref = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa_4096_0eefa619-50b7-588f-a072-d405fb439d36"
	base := strings.Replace(validConfig,
		"containers:\n",
		"models:\n  - name: private-model\n    repo: org/model@revision\n    emwp: "+ref+"\n    key-secret: MODEL_KEY\ncontainers:\n",
		1,
	)

	for _, test := range []struct {
		name string
		yaml string
		want string
	}{
		{name: "explicit grant", yaml: strings.Replace(base, "networks: [app]", "networks: [app]\n    models: [private-model]", 1)},
		{name: "encrypted model without grant", yaml: base, want: "requires an explicit container grant"},
		{name: "unknown model", yaml: strings.Replace(base, "networks: [app]", "networks: [app]\n    models: [unknown]", 1), want: "is not declared"},
		{name: "duplicate grant", yaml: strings.Replace(base, "networks: [app]", "networks: [app]\n    models: [private-model, private-model]", 1), want: "is duplicated"},
		{name: "invalid name", yaml: strings.Replace(strings.Replace(base, "private-model", "../private", 1), "networks: [app]", "networks: [app]\n    models: [../private]", 1), want: "\"../private\" is invalid"},
		{name: "duplicate model", yaml: strings.Replace(strings.Replace(base, "containers:\n", "  - name: private-model\n    mwp: "+ref+"\ncontainers:\n", 1), "networks: [app]", "networks: [app]\n    models: [private-model]", 1), want: "duplicates"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := Decode(asJSON(t, test.yaml), false)
			if test.want == "" && err != nil {
				t.Fatal(err)
			}
			if test.want != "" && (err == nil || !strings.Contains(err.Error(), test.want)) {
				t.Fatalf("error = %v, want substring %q", err, test.want)
			}
		})
	}

	plaintext := strings.Replace(validConfig, "containers:\n", "models:\n  - name: public-model\n    mwp: "+ref+"\ncontainers:\n", 1)
	if _, err := Decode(asJSON(t, plaintext), false); err != nil {
		t.Fatalf("legacy plaintext model without grant: %v", err)
	}
	namelessPlaintext := strings.Replace(plaintext, "  - name: public-model\n    mwp:", "  - mwp:", 1)
	if _, err := Decode(asJSON(t, namelessPlaintext), false); err != nil {
		t.Fatalf("legacy nameless plaintext model: %v", err)
	}
}

func TestDecodeValidatesGPUSelections(t *testing.T) {
	base := strings.Replace(validConfig, versionLine, versionLine+"\ngpus: 2", 1)
	for _, test := range []struct {
		name      string
		selection string
		want      string
	}{
		{name: "count", selection: "2"},
		{name: "all", selection: "all"},
		{name: "ids", selection: "0,1"},
		{name: "negative", selection: "-1", want: "between 1 and 2"},
		{name: "zero", selection: "0", want: "between 1 and 2"},
		{name: "too many", selection: "3", want: "between 1 and 2"},
		{name: "out of range id", selection: "0,2", want: "outside 0..1"},
		{name: "duplicate id", selection: "1,1", want: "duplicated"},
		{name: "boolean", selection: "true", want: "positive count"},
		{name: "empty id", selection: `"0,"`, want: "invalid device ID"},
	} {
		t.Run(test.name, func(t *testing.T) {
			yaml := strings.Replace(base, "networks: [app]", "networks: [app]\n    runtime: nvidia\n    gpus: "+test.selection, 1)
			_, err := Decode(asJSON(t, yaml), false)
			if test.want == "" && err != nil {
				t.Fatal(err)
			}
			if test.want != "" && (err == nil || !strings.Contains(err.Error(), test.want)) {
				t.Fatalf("error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestDecodeDefaultsNullNetworkBeforeValidation(t *testing.T) {
	config, err := Decode(configtest.JSON(t, strings.Replace(validConfig, "app:\n    egress: closed", "app:", 1)), false)
	if err != nil {
		t.Fatal(err)
	}
	if config.Networks["app"] == nil || config.Networks["app"].Egress != "closed" {
		t.Fatalf("network default = %#v", config.Networks["app"])
	}
}

func TestDecodeRejectsRepeatedMember(t *testing.T) {
	const name = `"name":"app"`
	repeated := strings.Replace(string(asJSON(t, validConfig)), name, name+","+name, 1)
	_, err := Decode([]byte(repeated), false)
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("error = %v", err)
	}
}

func TestDecodeRejectsMultipleDocuments(t *testing.T) {
	for _, trailing := range []string{"{}", "\n---\n{}\n"} {
		if _, err := Decode(append(asJSON(t, validConfig), trailing...), false); err == nil {
			t.Fatalf("config followed by %q accepted", trailing)
		}
	}
}

func TestDecodeTakesOnlyJSONConfigs(t *testing.T) {
	earlier := strings.Replace(validConfig, configtest.CVMVersion, configtest.YAMLCVMVersion, 1)
	unversioned := strings.Replace(validConfig, versionLine, "", 1)
	for _, test := range []struct {
		name string
		data []byte
		want string
	}{
		{name: "YAML", data: []byte(validConfig), want: "take a JSON config"},
		{name: "YAML for an earlier runtime", data: []byte(earlier), want: "this runtime takes a JSON config"},
		{name: "JSON for an earlier runtime", data: asJSON(t, earlier), want: "this runtime takes a JSON config"},
		{name: "YAML without a version", data: []byte(unversioned), want: "this runtime takes a JSON config"},
		{name: "JSON without a version", data: asJSON(t, unversioned), want: "this runtime takes a JSON config"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := Decode(test.data, false)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want substring %q", err, test.want)
			}
		})
	}
}
