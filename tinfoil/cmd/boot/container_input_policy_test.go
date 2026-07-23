package main

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestContainerInputPolicyPreservesKnownProductionInputs(t *testing.T) {
	config := decodePolicyConfig(t, `
containers:
  - name: workload
    image: example.invalid/workload
    ipc: host
    volumes:
      - execsock:/run/execsock
    cap_add:
      - CHOWN
      - DAC_OVERRIDE
      - IPC_LOCK
      - KILL
      - NET_BIND_SERVICE
      - SETGID
      - SETUID
      - SYS_NICE
      - SYS_RESOURCE
`)
	if err := validateConfigShapeForMode(&config, false); err != nil {
		t.Fatalf("validateConfigShape rejected known production inputs: %v", err)
	}
}

func TestContainerInputPolicyRejectsUnsupportedInputs(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{name: "host pid", body: "pid: host", want: ".pid is unsupported"},
		{name: "device", body: "devices: [/dev/kvm]", want: ".devices is unsupported"},
		{name: "privileged true", body: "privileged: true", want: ".privileged is unsupported"},
		{name: "privileged false", body: "privileged: false", want: ".privileged is unsupported"},
		{name: "cap drop", body: "cap_drop: [NET_RAW]", want: ".cap_drop is unsupported"},
		{name: "empty cap drop", body: "cap_drop: []", want: ".cap_drop is unsupported"},
		{name: "security opt", body: "security_opt: [seccomp=unconfined]", want: ".security_opt is unsupported"},
		{name: "empty security opt", body: "security_opt: []", want: ".security_opt is unsupported"},
		{name: "shared ipc", body: "ipc: shareable", want: ".ipc must be private or host"},
		{name: "absolute bind", body: "volumes: [/:/host]", want: "named volume source"},
		{name: "relative bind", body: "volumes: [./data:/data]", want: "named volume source"},
		{name: "slash bind", body: "volumes: [data/cache:/cache]", want: "named volume source"},
		{name: "docker socket", body: "volumes: [/var/run/docker.sock:/var/run/docker.sock]", want: "named volume source"},
		{name: "anonymous volume", body: "volumes: [/data]", want: "named volume source"},
		{name: "sys admin", body: "cap_add: [SYS_ADMIN]", want: `capability "SYS_ADMIN" is unsupported`},
		{name: "sys module", body: "cap_add: [SYS_MODULE]", want: `capability "SYS_MODULE" is unsupported`},
		{name: "cap prefix alias", body: "cap_add: [CAP_CHOWN]", want: `capability "CAP_CHOWN" is unsupported`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := decodePolicyConfig(t, "containers:\n  - name: workload\n    image: example.invalid/workload\n    "+test.body+"\n")
			err := validateConfigShapeForMode(&config, false)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("validateConfigShape error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestContainerInputPolicyDebugSocketPolicy(t *testing.T) {
	tests := []struct {
		name  string
		debug bool
		body  string
		want  string
	}{
		{name: "production rejects socket bind", body: "volumes: [/run/docker.sock:/var/run/docker.sock]", want: "named volume source"},
		{name: "debug accepts exact socket bind", debug: true, body: "volumes: [/run/docker.sock:/var/run/docker.sock]"},
		{name: "debug rejects rw socket bind alias", debug: true, body: "volumes: [/run/docker.sock:/var/run/docker.sock:rw]", want: "named volume source"},
		{name: "debug rejects source alias", debug: true, body: "volumes: [/var/run/docker.sock:/var/run/docker.sock]", want: "named volume source"},
		{name: "debug rejects target alias", debug: true, body: "volumes: [/run/docker.sock:/run/docker.sock]", want: "named volume source"},
		{name: "debug rejects read-only socket bind", debug: true, body: "volumes: [/run/docker.sock:/var/run/docker.sock:ro]", want: "named volume source"},
		{name: "debug rejects extra options", debug: true, body: "volumes: [/run/docker.sock:/var/run/docker.sock:rw,z]", want: "named volume source"},
		{name: "debug rejects other host bind", debug: true, body: "volumes: [/tmp:/tmp]", want: "named volume source"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := decodePolicyConfig(t, "containers:\n  - name: workload\n    image: example.invalid/workload\n    "+test.body+"\n")
			err := validateConfigShapeForMode(&config, test.debug)
			if test.want == "" {
				if err != nil {
					t.Fatalf("validateConfigShapeForMode rejected %s: %v", test.name, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("validateConfigShapeForMode error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestContainerInputPolicyRejectsYAMLMergeKeysBeforeDecode(t *testing.T) {
	tests := []struct {
		name  string
		merge string
	}{
		{name: "privileged", merge: "{privileged: true}"},
		{name: "cap drop", merge: "{cap_drop: [NET_RAW]}"},
		{name: "security opt", merge: "{security_opt: [seccomp=unconfined]}"},
		{name: "otherwise supported fields", merge: "{ipc: host}"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data := "containers:\n  - name: workload\n    image: example.invalid/workload\n    <<: " + test.merge + "\n"
			var config Config
			err := yaml.Unmarshal([]byte(data), &config)
			if err == nil || !strings.Contains(err.Error(), "container YAML merge keys are unsupported") {
				t.Fatalf("yaml.Unmarshal error = %v, want merge-key rejection", err)
			}
		})
	}
}

func TestValidNamedVolume(t *testing.T) {
	for _, name := range []string{"execsock", "a", "model-cache.v2", "cache_1"} {
		if !validNamedVolume(name) {
			t.Errorf("validNamedVolume(%q) = false", name)
		}
	}
	for _, name := range []string{"", ".", "..", "./data", "../data", "data/cache", "/data", "-cache", "cache:name"} {
		if validNamedVolume(name) {
			t.Errorf("validNamedVolume(%q) = true", name)
		}
	}
}

func TestContainerInputPolicyRejectsDuplicateReservedName(t *testing.T) {
	config := decodePolicyConfig(t, `
containers:
  - name: tinfoil-ssh-installer
    image: example.invalid/installer
  - name: tinfoil-ssh-installer
    image: example.invalid/installer
`)
	err := validateConfigShapeForMode(&config, true)
	if err == nil || !strings.Contains(err.Error(), `duplicates`) {
		t.Fatalf("validateConfigShapeForMode error = %v, want duplicate-name rejection", err)
	}
}

func decodePolicyConfig(t *testing.T, data string) Config {
	t.Helper()
	var config Config
	if err := yaml.Unmarshal([]byte(data), &config); err != nil {
		t.Fatalf("yaml.Unmarshal: %v", err)
	}
	return config
}
