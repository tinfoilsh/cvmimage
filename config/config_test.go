package tinfoilconfig

import (
	"fmt"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const validConfig = `
cvm-version: 0.11.0
cpus: 8
memory: 16384
keyserver-url: https://keys.example.com
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

func TestDecodeValidation(t *testing.T) {
	for _, test := range []struct {
		name    string
		yaml    string
		options Options
		want    string
	}{
		{name: "valid", yaml: validConfig},
		{name: "obsolete vault URL", yaml: validConfig + "vault-url: https://keys.example.com\n", want: "field vault-url not found"},
		{name: "unknown top-level field", yaml: validConfig + "unknown: true\n", want: "field unknown not found"},
		{name: "unknown container field", yaml: strings.Replace(validConfig, "networks: [app]", "networks: [app]\n    typo: true", 1), want: "unknown container field"},
		{name: "mutable image", yaml: strings.Replace(validConfig, "example.com/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "example.com/app:latest", 1), want: "immutable digest"},
		{name: "host socket rejected", yaml: strings.Replace(validConfig, "networks: [app]", "networks: [app]\n    volumes: [/run/docker.sock:/var/run/docker.sock]", 1), want: "must name a volume declared in volumes"},
		{name: "trusted debug socket accepted", options: Options{Mode: HostDebugMode}, yaml: strings.Replace(validConfig, "name: app\n    image", fmt.Sprintf("name: %s\n    volumes: [/run/docker.sock:/var/run/docker.sock]\n    image", ReservedDebugContainerName), 1)},
		{name: "other host socket rejected in debug mode", options: Options{Mode: HostDebugMode}, yaml: strings.Replace(validConfig, "networks: [app]", "networks: [app]\n    volumes: [/etc:/host]", 1), want: "must name a volume declared in volumes"},
		{name: "declared volume attached", yaml: strings.Replace(validConfig, "networks: [app]", "networks: [app]\n    volumes: [state:/var/lib/app]", 1) + "volumes:\n  - name: state\n    exec: true\n"},
		{name: "undeclared volume attached", yaml: strings.Replace(validConfig, "networks: [app]", "networks: [app]\n    volumes: [state:/var/lib/app]", 1), want: "must name a volume declared in volumes"},
		{name: "volume mount path not absolute", yaml: strings.Replace(validConfig, "networks: [app]", "networks: [app]\n    volumes: [state:var/lib/app]", 1) + "volumes:\n  - name: state\n", want: "clean absolute path"},
		{name: "volume name rejected", yaml: validConfig + "volumes:\n  - name: State\n", want: "must be lowercase alphanumeric"},
		{name: "volume owner rejected", yaml: validConfig + "volumes:\n  - name: state\n    owner: 70000\n", want: "owner must be between"},
		{name: "volume declared twice", yaml: validConfig + "volumes:\n  - name: state\n  - name: state\n", want: "declared twice"},
		{name: "unknown volume field", yaml: validConfig + "volumes:\n  - name: state\n    sized: 10\n", want: "field sized not found"},
		{name: "volume size accepted", yaml: validConfig + "volumes:\n  - name: state\n    size: 500GiB\n"},
		{name: "volume size without unit", yaml: validConfig + "volumes:\n  - name: state\n    size: 10\n", want: "needs a unit"},
		{name: "volume size too small", yaml: validConfig + "volumes:\n  - name: state\n    size: 4MiB\n", want: "below the minimum"},
		{name: "multiple documents", yaml: validConfig + "\n---\n{}\n", want: "multiple YAML documents"},
		{name: "model schema accepted", yaml: validConfig + "models:\n  - repo: org/model@revision\n    schema: 2\n"},
		{name: "negative model schema", yaml: validConfig + "models:\n  - repo: org/model@revision\n    schema: -1\n", want: "schema must be a positive integer"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := Decode([]byte(test.yaml), test.options)
			if test.want == "" && err != nil {
				t.Fatal(err)
			}
			if test.want != "" && (err == nil || !strings.Contains(err.Error(), test.want)) {
				t.Fatalf("error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestDecodeSetsDefaults(t *testing.T) {
	config, err := Decode([]byte(validConfig), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if config.ShimCfg.UpstreamContainer != "app" {
		t.Fatalf("upstream container = %q", config.ShimCfg.UpstreamContainer)
	}
	if config.ShimCfg.TLSMode != "cert-proxy" || !config.ShimCfg.PublishAttestation {
		t.Fatalf("shim defaults = %#v", config.ShimCfg)
	}
	if config.KeyserverURL != "https://keys.example.com" {
		t.Fatalf("keyserver URL = %q", config.KeyserverURL)
	}
}

func TestContainerAttestation(t *testing.T) {
	for _, test := range []struct {
		name    string
		fields  string
		want    bool
		wantErr string
	}{
		{name: "absent"},
		{name: "disabled", fields: "    attestation: false\n"},
		{name: "enabled", fields: "    attestation: true\n", want: true},
		{name: "invalid string", fields: "    attestation: invalid\n", wantErr: "cannot unmarshal"},
		{name: "number", fields: "    attestation: 1\n", wantErr: "cannot unmarshal"},
		{name: "sequence", fields: "    attestation: []\n", wantErr: "cannot unmarshal"},
		{name: "mapping", fields: "    attestation: {}\n", wantErr: "cannot unmarshal"},
		{name: "duplicate", fields: "    attestation: true\n    attestation: false\n", wantErr: "duplicate container field"},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg, err := Decode([]byte(validConfig+test.fields), Options{})
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("error = %v, want substring %q", err, test.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := cfg.Containers[0].Attestation; got != test.want {
				t.Fatalf("attestation = %v, want %v", got, test.want)
			}
		})
	}
}

func TestCVMAdminPolicy(t *testing.T) {
	admin := strings.Replace(validConfig, "    networks: [app]", "    cvm_admin: true", 1)
	for _, test := range []struct {
		name string
		yaml string
		want string
	}{
		{name: "admin", yaml: admin},
		{name: "explicit root", yaml: admin + "    user: '0:0'\n"},
		{name: "read only opt in", yaml: admin + "    read_only: true\n"},
		{name: "no host Docker socket", yaml: admin + "    volumes: [/run/docker.sock:/var/run/docker.sock]\n", want: "must name a volume declared"},
		{name: "no host manager socket", yaml: admin + "    volumes: [/run/tinfoil/containers.sock:/run/tinfoil/containers.sock]\n", want: "must name a volume declared"},
		{name: "attached volume", yaml: admin + "    volumes: [workspace:/run/tinfoil/volumedata/workspace]\nvolumes:\n  - name: workspace\n    exec: true\n"},
		{name: "non root", yaml: admin + "    user: '1000'\n", want: "requires root user"},
		{name: "non root group", yaml: admin + "    user: '0:1000'\n", want: "requires root user"},
		{name: "bridge", yaml: admin + "    networks: [app]\n"},
		{name: "SSH port mapping", yaml: admin + "    networks: [app]\n    ports: ['2022:2222']\n"},
		{name: "port without network", yaml: admin + "    ports: ['2022:2222']\n", want: "requires an attached network"},
		{name: "reserved host port", yaml: admin + "    networks: [app]\n    ports: ['2222:2222']\n", want: "reserved"},
		{name: "undeclared network", yaml: admin + "    networks: [missing]\n", want: "not declared"},
		{name: "undeclared volume", yaml: admin + "    volumes: [missing:/workspace]\n", want: "must name a volume declared"},
		{name: "arbitrary host bind", yaml: admin + "    volumes: [/etc:/etc]\n", want: "must name a volume declared"},
		{name: "mutable image", yaml: strings.Replace(admin, "@sha256:"+strings.Repeat("a", 64), ":latest", 1), want: "immutable digest"},
		{name: "unknown field", yaml: admin + "    typo: true\n", want: "unknown container field"},
		{name: "duplicate flag", yaml: admin + "    cvm_admin: false\n", want: "duplicate container field"},
		{name: "invalid flag", yaml: strings.Replace(admin, "cvm_admin: true", "cvm_admin: invalid", 1), want: "cannot unmarshal"},
		{name: "not generic privileged syntax", yaml: admin + "    privileged: true\n", want: "privileged is unsupported"},
		{name: "false keeps socket closed", yaml: strings.Replace(admin, "cvm_admin: true", "cvm_admin: false", 1) + "    volumes: [/run/docker.sock:/var/run/docker.sock]\n", want: "must name a volume declared"},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg, err := Decode([]byte(test.yaml), Options{})
			if test.want != "" {
				if err == nil || !strings.Contains(err.Error(), test.want) {
					t.Fatalf("error = %v, want substring %q", err, test.want)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !cfg.Containers[0].CVMAdmin {
				t.Fatal("admin permission lost during decode")
			}
		})
	}
	cfg, err := Decode([]byte(validConfig), Options{})
	if err != nil || cfg.Containers[0].CVMAdmin {
		t.Fatalf("ordinary config acquired admin permission: cfg=%+v err=%v", cfg, err)
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
		{name: "invalid name", yaml: strings.Replace(strings.Replace(base, "private-model", "../private", 1), "networks: [app]", "networks: [app]\n    models: [../private]", 1), want: "is invalid"},
		{name: "duplicate model", yaml: strings.Replace(strings.Replace(base, "containers:\n", "  - name: private-model\n    mwp: "+ref+"\ncontainers:\n", 1), "networks: [app]", "networks: [app]\n    models: [private-model]", 1), want: "duplicates"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := Decode([]byte(test.yaml), Options{})
			if test.want == "" && err != nil {
				t.Fatal(err)
			}
			if test.want != "" && (err == nil || !strings.Contains(err.Error(), test.want)) {
				t.Fatalf("error = %v, want substring %q", err, test.want)
			}
		})
	}

	plaintext := strings.Replace(validConfig, "containers:\n", "models:\n  - name: public-model\n    mwp: "+ref+"\ncontainers:\n", 1)
	config, err := Decode([]byte(plaintext), Options{})
	if err != nil {
		t.Fatalf("legacy plaintext model without grant: %v", err)
	}
	if ModelIsIsolated(config, "public-model") {
		t.Fatal("legacy plaintext model is isolated")
	}

	isolatedPlaintext := strings.Replace(plaintext, "networks: [app]", "networks: [app]\n    models: [public-model]", 1)
	config, err = Decode([]byte(isolatedPlaintext), Options{})
	if err != nil {
		t.Fatalf("isolated plaintext model: %v", err)
	}
	if !ModelIsIsolated(config, "public-model") {
		t.Fatal("explicitly granted plaintext model is not isolated")
	}

	namelessPlaintext := strings.Replace(plaintext, "  - name: public-model\n    mwp:", "  - mwp:", 1)
	if _, err := Decode([]byte(namelessPlaintext), Options{}); err != nil {
		t.Fatalf("legacy nameless plaintext model: %v", err)
	}
}

func TestDecodeShimRejectsNilNode(t *testing.T) {
	_, err := DecodeShim(nil)
	if err == nil || !strings.Contains(err.Error(), "missing YAML document") {
		t.Fatalf("error = %v, want missing YAML document", err)
	}
}

func TestParseSize(t *testing.T) {
	for text, want := range map[string]int64{
		"30GiB": 30 << 30, "16TB": 16_000_000_000_000, "1.5T": 3 << 39, "512m": 512 << 20,
		" 64 MiB ": 64 << 20, "2tib": 2 << 40, "1000000000B": 1_000_000_000,
	} {
		got, err := ParseSize(text)
		if err != nil || got != want {
			t.Errorf("ParseSize(%q) = %d, %v; want %d", text, got, err, want)
		}
	}
	for text, want := range map[string]string{
		"": "empty", "10": "needs a unit", "GiB": "no number", "-1GiB": "positive", "0GiB": "positive",
		"1.5KB": "multiple of 512", "1PB": "unknown unit", "32MiB": "below the minimum", "1.0000001GiB": "whole number",
		"99999999999TiB": "too large",
	} {
		if _, err := ParseSize(text); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("ParseSize(%q) error = %v; want substring %q", text, err, want)
		}
	}
	spec := VolumeSpec{Name: "state"}
	if n, err := spec.SizeBytes(); n != 0 || err != nil {
		t.Errorf("empty size should mean the host default, got %d, %v", n, err)
	}
}

func keyConfig() string {
	return validConfig +
		"    keys: [host-ssh]\nattested-keys:\n  - id: host-ssh\n    key: ecdsa-p256\n"
}

func TestAttestedKeyConfig(t *testing.T) {
	valid := keyConfig()
	for _, tc := range []struct{ name, input, want string }{
		{"valid", valid, ""},
		{"ed25519", strings.Replace(valid, "ecdsa-p256", "ed25519", 1), ""},
		{"x25519", strings.Replace(valid, "ecdsa-p256", "x25519", 1), ""},
		{"ownership", valid + "    uid: 1000\n    gid: 1001\n", ""},
		{"missing id", strings.ReplaceAll(valid, "host-ssh", ""), "safe lowercase"},
		{"reserved tls", strings.ReplaceAll(valid, "host-ssh", "tls"), "safe lowercase"},
		{"reserved hpke", strings.ReplaceAll(valid, "host-ssh", "hpke"), "safe lowercase"},
		{"path traversal", strings.ReplaceAll(valid, "host-ssh", "../other"), "safe lowercase"},
		{"unknown algorithm", strings.Replace(valid, "ecdsa-p256", "rsa", 1), "unsupported"},
		{"unknown format", valid + "    credential: openssh\n", "field credential not found"},
		{"duplicate declaration", valid + "  - id: host-ssh\n    key: ed25519\n", "declared twice"},
		{"missing grant", strings.Replace(valid, "    keys: [host-ssh]\n", "", 1), "exactly one container grant"},
		{"unknown grant", strings.Replace(valid, "keys: [host-ssh]", "keys: [other]", 1), "unknown attested key"},
		{"duplicate grant", strings.Replace(valid, "keys: [host-ssh]", "keys: [host-ssh, host-ssh]", 1), "duplicate or shared grant"},
		{"negative uid", valid + "    uid: -1\n", "uid and gid"},
		{"large gid", valid + "    gid: 65535\n", "uid and gid"},
		{"run tmpfs", strings.Replace(valid, "    keys:", "    tmpfs: {/run: rw}\n    keys:", 1), ""},
		{"key tmpfs", strings.Replace(valid, "    keys:", "    tmpfs: {/run/tinfoil/keys: rw}\n    keys:", 1), "conflicts with attested key"},
		{"parent tmpfs", strings.Replace(valid, "    keys:", "    tmpfs: {/run/tinfoil: rw}\n    keys:", 1), "conflicts with attested key"},
		{"child tmpfs", strings.Replace(valid, "    keys:", "    tmpfs: {/run/tinfoil/keys/host-ssh/private_key.pem: rw}\n    keys:", 1), "conflicts with attested key"},
		{"volume parent", strings.Replace(valid, "    keys:", "    volumes: [state:/run]\n    keys:", 1) + "volumes: [{name: state}]\n", "conflicts with attested key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := Decode([]byte(tc.input), Options{})
			if tc.want != "" {
				if err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("got %v, want %q", err, tc.want)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := yaml.Marshal(cfg)
			if err != nil {
				t.Fatal(err)
			}
			roundTrip, err := Decode(encoded, Options{})
			if err != nil {
				t.Fatal(err)
			}
			if len(roundTrip.AttestedKeys) != 1 || roundTrip.AttestedKeys[0] != cfg.AttestedKeys[0] || len(roundTrip.Containers[0].Keys) != 1 {
				t.Fatal("round trip dropped declaration or grant")
			}
		})
	}
}

func TestAttestedKeyLimitsAndSharing(t *testing.T) {
	cfg, err := Decode([]byte(keyConfig()), Options{})
	if err != nil {
		t.Fatal(err)
	}
	other := cfg.Containers[0]
	other.Name = "other"
	cfg.Containers = append(cfg.Containers, other)
	if err := Validate(cfg, Options{}); err == nil || !strings.Contains(err.Error(), "shared grant") {
		t.Fatalf("shared grant accepted: %v", err)
	}
	cfg.Containers = cfg.Containers[:1]
	cfg.AttestedKeys, cfg.Containers[0].Keys = nil, nil
	for i := 0; i <= MaxAttestedKeys; i++ {
		id := fmt.Sprintf("key-%d", i)
		cfg.AttestedKeys = append(cfg.AttestedKeys, AttestedKey{ID: id, Key: KeyEd25519})
		cfg.Containers[0].Keys = append(cfg.Containers[0].Keys, id)
	}
	if err := Validate(cfg, Options{}); err == nil || !strings.Contains(err.Error(), "exceeds limit") {
		t.Fatalf("excessive keys accepted: %v", err)
	}
}

func TestAdminSSH(t *testing.T) {
	base := validConfig + "    cvm_admin: true\n    ports: ['22:22', '3000:3000']\ncvm-network:\n  inbound-ports: [22]\n"
	for _, tc := range []struct {
		name, input string
		enabled     bool
		want        string
	}{
		{"enabled", base, true, ""},
		{"no inbound opt-in", strings.Replace(base, "inbound-ports: [22]", "inbound-ports: []", 1), false, ""},
		{"ordinary container", strings.Replace(base, "cvm_admin: true", "cvm_admin: false", 1), false, ""},
		{"different published port", strings.Replace(base, "'22:22'", "'2022:22'", 1), false, ""},
		{"wrong target", strings.Replace(base, "'22:22'", "'22:2222'", 1), false, "requires 22:22"},
		{"duplicate mapping", strings.Replace(base, "'3000:3000'", "'22:22'", 1), false, "already published"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := Decode([]byte(tc.input), Options{})
			if tc.want != "" {
				if err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("got %v, want %q", err, tc.want)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			mapping, err := AdminSSH(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if (mapping != nil) != tc.enabled {
				t.Fatalf("mapping = %+v", mapping)
			}
			if mapping != nil && (mapping.Container != "app" || mapping.GuestPort != 22 || mapping.ContainerPort != 22) {
				t.Fatalf("wrong target: %+v", mapping)
			}
		})
	}
}
