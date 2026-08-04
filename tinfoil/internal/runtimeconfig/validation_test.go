package runtimeconfig

import (
	"fmt"
	"strings"
	"testing"
)

func TestDecodeRejectsUnknownHealthcheckField(t *testing.T) {
	_, err := Decode([]byte(`
shim: {}
containers:
  - name: app
    image: example.com/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    healthcheck:
      test: [CMD, ok]
      retrise: 3
`), false)
	if err == nil || !strings.Contains(err.Error(), `unknown healthcheck field "retrise"`) {
		t.Fatalf("Decode error = %v", err)
	}
}

const validConfig = `
cvm-version: 0.11.0
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
		{name: "unknown field", yaml: validConfig + "unknown: true\n", want: "field unknown not found"},
		{name: "unknown container field", yaml: strings.Replace(validConfig, "networks: [app]", "networks: [app]\n    typo: true", 1), want: "unknown container field"},
		{name: "duplicate container field", yaml: strings.Replace(validConfig, "networks: [app]", "image: duplicate\n    networks: [app]", 1), want: "duplicate container field"},
		{name: "container merge key", yaml: "defaults: &defaults\n  image: example.com/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n" + strings.Replace(validConfig, "    image: example.com/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "    <<: *defaults", 1), want: "merge keys are unsupported"},
		{name: "duplicate container", yaml: strings.Replace(validConfig, "containers:\n", "containers:\n  - name: app\n    image: example.com/duplicate@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n", 1), want: "duplicates"},
		{name: "mutable image", yaml: strings.Replace(validConfig, "example.com/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "example.com/app:latest", 1), want: "immutable digest"},
		{name: "debug mutable image", debug: true, yaml: strings.Replace(validConfig, "example.com/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "example.com/app:latest", 1)},
		{name: "undeclared network", yaml: strings.Replace(validConfig, "networks: [app]", "networks: [missing]", 1), want: "not declared"},
		{name: "production docker socket", yaml: strings.Replace(validConfig, "networks: [app]", "networks: [app]\n    volumes: [/run/docker.sock:/var/run/docker.sock]", 1), want: "named volume"},
		{name: "volume outside data", yaml: strings.Replace(validConfig, "networks: [app]", "networks: [app]\n    volumes: [state:/etc]", 1), want: "below /data"},
		{name: "volume invalid mode", yaml: strings.Replace(validConfig, "networks: [app]", "networks: [app]\n    volumes: [state:/data:shared]", 1), want: "ro or rw"},
		{name: "writable rootfs", yaml: strings.Replace(validConfig, "networks: [app]", "networks: [app]\n    read_only: false", 1), want: "read-only root filesystem"},
		{name: "debug toolbox socket", debug: true, yaml: strings.Replace(validConfig, "name: app\n    image", fmt.Sprintf("name: %s\n    volumes: [/run/docker.sock:/var/run/docker.sock]\n    image", ReservedDebugContainerName), 1)},
		{name: "host ipc", yaml: strings.Replace(validConfig, "networks: [app]", "networks: [app]\n    ipc: host", 1), want: "ipc must be private or none"},
		{name: "host pid", yaml: strings.Replace(validConfig, "networks: [app]", "networks: [app]\n    pid: host", 1), want: "pid is unsupported"},
		{name: "raw device", yaml: strings.Replace(validConfig, "networks: [app]", "networks: [app]\n    devices: [/dev/kvm]", 1), want: "devices is unsupported"},
		{name: "implicit runtime alias", yaml: strings.Replace(validConfig, "networks: [app]", "networks: [app]\n    runtime: attacker.runc.v2", 1), want: "runtime"},
		{name: "nvidia runtime without selection", yaml: strings.Replace(validConfig, "networks: [app]", "networks: [app]\n    runtime: nvidia", 1), want: "explicit gpus selection"},
		{name: "gpu selection without runtime", yaml: strings.Replace(validConfig, "networks: [app]", "networks: [app]\n    gpus: all", 1), want: "declares no GPUs"},
		{name: "valid top-level gpu count", yaml: strings.Replace(validConfig, "cvm-version: 0.11.0", "cvm-version: 0.11.0\ngpus: 2", 1) + "\n", want: ""},
		{name: "unsupported capability", yaml: strings.Replace(validConfig, "networks: [app]", "networks: [app]\n    cap_add: [SETUID]", 1), want: "capability"},
		{name: "invalid allowlist", yaml: strings.Replace(validConfig, "egress: closed", "egress: allowlist\n    allow: ['*.example.com']", 1), want: "wildcards"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := Decode([]byte(test.yaml), test.debug)
			if test.want == "" && err != nil {
				t.Fatal(err)
			}
			if test.want != "" && (err == nil || !strings.Contains(err.Error(), test.want)) {
				t.Fatalf("error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestDecodeRequiresExplicitModelAssignment(t *testing.T) {
	const modelRef = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa_4096_0eefa619-50b7-588f-a072-d405fb439d36"
	base := fmt.Sprintf(`
shim:
  upstream-port: 8080
models:
  - name: weights
    repo: org/weights@v1
    mwp: %s
containers:
  - name: app
    image: example.com/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    models: [weights]
`, modelRef)
	if _, err := Decode([]byte(base), false); err != nil {
		t.Fatalf("valid model assignment rejected: %v", err)
	}
	if _, err := Decode([]byte(strings.Replace(base, "models: [weights]", "models: [missing]", 1)), false); err == nil || !strings.Contains(err.Error(), "unknown model") {
		t.Fatalf("unknown model error = %v", err)
	}
	if _, err := Decode([]byte(strings.Replace(base, "models: [weights]", "models: [weights, weights]", 1)), false); err == nil || !strings.Contains(err.Error(), "duplicates model") {
		t.Fatalf("duplicate model error = %v", err)
	}
}

func TestDecodePermitsOnlyOneWritableVolumeOwner(t *testing.T) {
	config := validConfig + `
  - name: reader
    image: example.com/reader@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
    volumes: [state:/data:ro]
`
	config = strings.Replace(config, "networks: [app]", "networks: [app]\n    volumes: [state:/data:rw]", 1)
	if _, err := Decode([]byte(config), false); err != nil {
		t.Fatalf("single writer with reader rejected: %v", err)
	}
	config = strings.Replace(config, "state:/data:ro", "state:/data:rw", 1)
	if _, err := Decode([]byte(config), false); err == nil || !strings.Contains(err.Error(), "writable after") {
		t.Fatalf("second writer error = %v", err)
	}
}

func TestDecodeValidatesGPUSelections(t *testing.T) {
	base := strings.Replace(validConfig, "cvm-version: 0.11.0", "cvm-version: 0.11.0\ngpus: 2", 1)
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
			_, err := Decode([]byte(yaml), false)
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
	config, err := Decode([]byte(strings.Replace(validConfig, "app:\n    egress: closed", "app:", 1)), false)
	if err != nil {
		t.Fatal(err)
	}
	if config.Networks["app"] == nil || config.Networks["app"].Egress != "closed" {
		t.Fatalf("network default = %#v", config.Networks["app"])
	}
}

func TestDecodeRejectsMultipleDocuments(t *testing.T) {
	_, err := Decode([]byte(validConfig+"\n---\n{}\n"), false)
	if err == nil || !strings.Contains(err.Error(), "multiple YAML documents") {
		t.Fatalf("error = %v", err)
	}
}
