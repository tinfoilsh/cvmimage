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
    image: example/app:latest
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
		{name: "unknown container field", yaml: strings.Replace(validConfig, "image: example/app:latest", "image: example/app:latest\n    typo: true", 1), want: "unknown container field"},
		{name: "duplicate container field", yaml: strings.Replace(validConfig, "image: example/app:latest", "image: example/app:latest\n    image: duplicate", 1), want: "duplicate container field"},
		{name: "container merge key", yaml: "defaults: &defaults\n  image: example/app:latest\n" + strings.Replace(validConfig, "image: example/app:latest", "<<: *defaults", 1), want: "merge keys are unsupported"},
		{name: "duplicate container", yaml: strings.Replace(validConfig, "containers:\n", "containers:\n  - name: app\n    image: duplicate\n", 1), want: "duplicates"},
		{name: "undeclared network", yaml: strings.Replace(validConfig, "networks: [app]", "networks: [missing]", 1), want: "not declared"},
		{name: "production docker socket", yaml: strings.Replace(validConfig, "networks: [app]", "networks: [app]\n    volumes: [/run/docker.sock:/var/run/docker.sock]", 1), want: "named volume"},
		{name: "debug toolbox socket", debug: true, yaml: strings.Replace(validConfig, "name: app\n    image", fmt.Sprintf("name: %s\n    volumes: [/run/docker.sock:/var/run/docker.sock]\n    image", ReservedDebugContainerName), 1)},
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
