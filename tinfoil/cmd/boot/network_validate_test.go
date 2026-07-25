package main

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	shimconfig "tinfoil/internal/config"
)

const (
	testMaxBridgeNameLength = 15
	testMaxHostnameLabel    = 63
	testMaxHostnameLength   = 253
)

func TestFixedNetworkInputLimits(t *testing.T) {
	if maxBridgeNameLen != testMaxBridgeNameLength {
		t.Fatalf("maxBridgeNameLen = %d, want fixed contract %d", maxBridgeNameLen, testMaxBridgeNameLength)
	}
	if maxHostnameLabel != testMaxHostnameLabel {
		t.Fatalf("maxHostnameLabel = %d, want fixed contract %d", maxHostnameLabel, testMaxHostnameLabel)
	}
	if maxHostnameLength != testMaxHostnameLength {
		t.Fatalf("maxHostnameLength = %d, want fixed contract %d", maxHostnameLength, testMaxHostnameLength)
	}
}

func TestIsNetworkName(t *testing.T) {
	t.Parallel()

	for _, value := range []string{"a", "0", "a0", "a-b", strings.Repeat("a", testMaxBridgeNameLength)} {
		if !isNetworkName(value) {
			t.Errorf("isNetworkName(%q) = false", value)
		}
	}
	for _, value := range []string{"", "A", "-a", "a-", "a.b", "a_b", "é", strings.Repeat("a", testMaxBridgeNameLength+1)} {
		if isNetworkName(value) {
			t.Errorf("isNetworkName(%q) = true", value)
		}
	}

	for character := 0; character <= 255; character++ {
		byteValue := byte(character)
		if got, want := isNetworkName(string([]byte{byteValue})), testLowerAlphanumeric(byteValue); got != want {
			t.Fatalf("isNetworkName single byte %#x = %t, want %t", character, got, want)
		}
		if got, want := isNetworkName(string([]byte{byteValue, 'b'})), testLowerAlphanumeric(byteValue); got != want {
			t.Fatalf("isNetworkName first byte %#x = %t, want %t", character, got, want)
		}
		wantInterior := testLowerAlphanumeric(byteValue) || byteValue == '-'
		if got := isNetworkName(string([]byte{'a', byteValue, 'b'})); got != wantInterior {
			t.Fatalf("isNetworkName interior byte %#x = %t, want %t", character, got, wantInterior)
		}
		if got, want := isNetworkName(string([]byte{'a', byteValue})), testLowerAlphanumeric(byteValue); got != want {
			t.Fatalf("isNetworkName final byte %#x = %t, want %t", character, got, want)
		}
	}
}

func TestIsRFC1123Hostname(t *testing.T) {
	t.Parallel()

	maxLengthHostname := strings.Repeat("a", testMaxHostnameLabel) + "." + strings.Repeat("b", testMaxHostnameLabel) + "." + strings.Repeat("c", testMaxHostnameLabel) + "." + strings.Repeat("d", 61)
	if len(maxLengthHostname) != testMaxHostnameLength {
		t.Fatalf("maximum hostname fixture is %d bytes, want %d", len(maxLengthHostname), testMaxHostnameLength)
	}
	for _, value := range []string{
		"a",
		"API.TINFOIL.SH",
		"a-b.example",
		strings.Repeat("a", testMaxHostnameLabel),
		maxLengthHostname,
	} {
		if !isRFC1123Hostname(value) {
			t.Errorf("isRFC1123Hostname(%q) = false", value)
		}
	}
	for _, value := range []string{
		"",
		".a",
		"a.",
		"a..b",
		"-a",
		"a-",
		"é",
		"K",
		"ſ",
		"a.K.example",
		"a.ſ.example",
		strings.Repeat("a", testMaxHostnameLabel+1),
		maxLengthHostname + "a",
	} {
		if isRFC1123Hostname(value) {
			t.Errorf("isRFC1123Hostname(%q) = true", value)
		}
	}

	for character := 0; character <= 255; character++ {
		byteValue := byte(character)
		wantAlphanumeric := testASCIIAlpha(byteValue) || testDigit(byteValue)
		if got := isRFC1123Hostname(string([]byte{byteValue})); got != wantAlphanumeric {
			t.Fatalf("isRFC1123Hostname single byte %#x = %t, want %t", character, got, wantAlphanumeric)
		}
		wantInterior := wantAlphanumeric || byteValue == '-' || byteValue == '.'
		if got := isRFC1123Hostname(string([]byte{'a', byteValue, 'b'})); got != wantInterior {
			t.Fatalf("isRFC1123Hostname interior byte %#x = %t, want %t", character, got, wantInterior)
		}
		if got := isRFC1123Hostname(string([]byte{'a', '.', byteValue})); got != wantAlphanumeric {
			t.Fatalf("isRFC1123Hostname label-first byte %#x = %t, want %t", character, got, wantAlphanumeric)
		}
		if got := isRFC1123Hostname(string([]byte{'a', byteValue})); got != wantAlphanumeric {
			t.Fatalf("isRFC1123Hostname final byte %#x = %t, want %t", character, got, wantAlphanumeric)
		}
	}
}

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
