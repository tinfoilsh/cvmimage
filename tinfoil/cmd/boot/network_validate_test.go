package main

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	shimconfig "tinfoil/internal/config"
)

// parseTestConfig mirrors loadAndVerifyConfig: unmarshal, decode shim,
// run validateNetwork. Uses raw YAML so tests exercise NetworkSpec's
// UnmarshalYAML default-egress behavior.
func parseTestConfig(t *testing.T, src string) (*Config, error) {
	t.Helper()
	var cfg Config
	if err := yaml.Unmarshal([]byte(src), &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if cfg.ShimRaw.Kind != 0 {
		s, err := shimconfig.Decode(&cfg.ShimRaw)
		if err == nil {
			cfg.ShimCfg = s
		}
	}
	return &cfg, validateNetwork(&cfg)
}

func mustReject(t *testing.T, src, errSub string) {
	t.Helper()
	_, err := parseTestConfig(t, src)
	if err == nil {
		t.Fatalf("expected error containing %q, got nil", errSub)
	}
	if !strings.Contains(err.Error(), errSub) {
		t.Fatalf("error %q should contain %q", err, errSub)
	}
}

func TestValidateNetwork_ReservedShimNet(t *testing.T) {
	mustReject(t, `
shim: {upstream-port: 8080}
networks: {shim-net: {}}
containers: [{name: app, image: nginx}]
`, "reserved")
}

func TestValidateNetwork_ContainerReferencesShimNet(t *testing.T) {
	mustReject(t, `
shim: {upstream-port: 8080}
networks: {control: {egress: closed}}
containers: [{name: app, image: nginx, networks: [control, shim-net]}]
`, "reserved")
}

func TestValidateNetwork_EgressDefaultsToClosed(t *testing.T) {
	src := `
shim: {upstream-port: 8080}
networks: {ipc-exec: {}}
containers: [{name: app, image: nginx, networks: [ipc-exec]}]
`
	cfg, err := parseTestConfig(t, src)
	if err != nil {
		t.Fatalf("expected accept, got: %v", err)
	}
	if cfg.Networks["ipc-exec"].Egress != "closed" {
		t.Fatalf("expected egress: closed default, got %+v", cfg.Networks["ipc-exec"])
	}
}

func TestValidateNetwork_EgressDefaultsOnNullBody(t *testing.T) {
	src := `
shim: {upstream-port: 8080}
networks:
  ipc-exec:
containers: [{name: app, image: nginx, networks: [ipc-exec]}]
`
	cfg, err := parseTestConfig(t, src)
	if err != nil {
		t.Fatalf("expected accept, got: %v", err)
	}
	if cfg.Networks["ipc-exec"].Egress != "closed" {
		t.Fatalf("expected egress: closed default on null body, got %+v", cfg.Networks["ipc-exec"])
	}
}

func TestValidateNetwork_InvalidEgressValue(t *testing.T) {
	mustReject(t, `
shim: {upstream-port: 8080}
networks: {weird: {egress: maybe}}
containers: [{name: app, image: nginx, networks: [weird]}]
`, "egress")
}

func TestValidateNetwork_AllowOnlyForAllowlist(t *testing.T) {
	mustReject(t, `
shim: {upstream-port: 8080}
networks: {control: {egress: open, allow: [api.tinfoil.sh]}}
containers: [{name: app, image: nginx, networks: [control]}]
`, "egress: allowlist")
}

func TestValidateNetwork_AllowHostnamesValidated(t *testing.T) {
	cases := []struct{ name, host, errSub string }{
		{"wildcard", "*.tinfoil.sh", "wildcards"},
		{"ip literal", "1.2.3.4", "IP literals"},
		{"empty", "", "empty"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			mustReject(t, `
shim: {upstream-port: 8080}
networks:
  control:
    egress: allowlist
    allow: ["`+c.host+`"]
containers: [{name: app, image: nginx, networks: [control]}]
`, c.errSub)
		})
	}
}

func TestValidateNetwork_ContainerRefsUnknownNetwork(t *testing.T) {
	mustReject(t, `
shim: {upstream-port: 8080}
networks: {control: {egress: allowlist, allow: [api.tinfoil.sh]}}
containers: [{name: app, image: nginx, networks: [control, mystery]}]
`, "mystery")
}

func TestValidateNetwork_SingleEgressClassEnforced(t *testing.T) {
	mustReject(t, `
shim: {upstream-port: 8080}
networks:
  control: {egress: allowlist, allow: [api.tinfoil.sh]}
  web: {egress: open}
containers: [{name: app, image: nginx, networks: [control, web]}]
`, "at most one")
}

func TestValidateNetwork_OneEgressPlusMultipleClosedIsFine(t *testing.T) {
	_, err := parseTestConfig(t, `
shim: {upstream-port: 8080}
networks:
  control: {egress: allowlist, allow: [api.tinfoil.sh]}
  ipc-a: {}
  ipc-b: {}
containers: [{name: app, image: nginx, networks: [control, ipc-a, ipc-b]}]
`)
	if err != nil {
		t.Fatalf("expected accept, got: %v", err)
	}
}

func TestValidateNetwork_InboundPortsRange(t *testing.T) {
	cases := []struct {
		port int
		ok   bool
	}{
		{1, true}, {65535, true},
		{0, false}, {-1, false}, {70000, false},
	}
	for _, c := range cases {
		cfg := Config{CVMNetwork: CVMNetworkConfig{InboundPorts: []int{c.port}}}
		err := validateNetwork(&cfg)
		if c.ok != (err == nil) {
			t.Errorf("port %d: ok=%v err=%v", c.port, c.ok, err)
		}
	}
}

func TestValidateNetwork_ShimUpstreamMustMatch(t *testing.T) {
	cfg := Config{
		ShimCfg: &shimconfig.Config{
			UpstreamPort:      8080,
			UpstreamContainer: "ghost",
			TLSMode:           "self-signed",
			TLSEnv:            "production",
			TLSChallengeMode:  "dns",
		},
		Containers: []Container{{Name: "real", Image: "nginx"}},
	}
	if err := validateNetwork(&cfg); err == nil {
		t.Fatal("expected error for non-existent upstream")
	}
}

func TestValidateNetwork_NetworkNameLength(t *testing.T) {
	tooLong := strings.Repeat("a", 16)
	mustReject(t, `
shim: {upstream-port: 8080}
networks:
  `+tooLong+`: {}
containers: [{name: app, image: nginx, networks: ["`+tooLong+`"]}]
`, "interface-name")
}

func TestValidateAllowEntry_LongHostnames(t *testing.T) {
	long := strings.Repeat("a.", 130) + "x" // 261 chars
	if err := validateAllowEntry(long); err == nil || !strings.Contains(err.Error(), "253-byte") {
		t.Fatalf("expected 253-byte error, got: %v", err)
	}
	if err := validateAllowEntry("api.tinfoil.sh"); err != nil {
		t.Fatalf("expected accept, got: %v", err)
	}
}

func TestValidateNetwork_AcceptsFullExample(t *testing.T) {
	_, err := parseTestConfig(t, `
shim: {upstream-port: 8080}
cvm-network: {inbound-ports: [9090]}
networks:
  control: {egress: allowlist, allow: [api.tinfoil.sh, buckets.tinfoil.sh]}
  web: {egress: open}
  ipc-exec: {}
containers:
  - {name: api-server, image: nginx, networks: [control, ipc-exec]}
  - {name: executor,   image: nginx, networks: [web, ipc-exec]}
  - {name: lonely,     image: nginx}
`)
	if err != nil {
		t.Fatalf("expected full §3.1 example to validate, got: %v", err)
	}
}
