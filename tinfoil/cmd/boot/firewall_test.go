package main

import (
	"strings"
	"testing"

	shimconfig "tinfoil/internal/config"
)

// renderFirewallScript returns the nft script setupContainerNetworkFirewall
// would commit, minus the runNft call.
func renderFirewallScript(cfg *Config) string {
	var s strings.Builder
	for name, spec := range cfg.Networks {
		writeBridgeRules(&s, name, spec)
	}
	if shimUpstreamSet(cfg) {
		writeBridgeRules(&s, "shim-net", &NetworkSpec{Egress: "closed"})
	}
	return s.String()
}

func TestFirewall_ClosedBridgeHasNoEgressRule(t *testing.T) {
	cfg := &Config{Networks: map[string]*NetworkSpec{
		"ipc-exec": {Egress: "closed"},
	}}
	script := renderFirewallScript(cfg)
	if !strings.Contains(script, `iif "ipc-exec" oif "ipc-exec" accept`) {
		t.Error("closed bridge should still allow intra-bridge traffic")
	}
	if !strings.Contains(script, `oif "ipc-exec" ct state established`) {
		t.Error("closed bridge should still allow return traffic")
	}
	if !strings.Contains(script, `input iif "ipc-exec" ct state new drop`) {
		t.Error("closed bridge should block container→host")
	}
	if strings.Contains(script, "ip daddr") {
		t.Errorf("closed bridge must not emit egress rules; got:\n%s", script)
	}
}

func TestFirewall_OpenBridgeEmitsPublicAccept(t *testing.T) {
	cfg := &Config{Networks: map[string]*NetworkSpec{
		"web": {Egress: "open"},
	}}
	script := renderFirewallScript(cfg)
	if !strings.Contains(script, `iif "web" ip daddr != { 10.0.0.0/8`) {
		t.Errorf("open bridge should accept public v4; got:\n%s", script)
	}
	if !strings.Contains(script, `iif "web" ip6 daddr != {`) {
		t.Error("open bridge should accept public v6")
	}
}

func TestFirewall_AllowlistEmitsSetAndAcceptRule(t *testing.T) {
	cfg := &Config{Networks: map[string]*NetworkSpec{
		"control": {Egress: "allowlist", Allow: []string{"api.tinfoil.sh"}},
	}}
	script := renderFirewallScript(cfg)
	if !strings.Contains(script, `add set inet tinfoil allow-control`) {
		t.Errorf("allowlist must declare its set; got:\n%s", script)
	}
	if !strings.Contains(script, `iif "control" ip daddr @allow-control accept`) {
		t.Errorf("allowlist must reference its set; got:\n%s", script)
	}
	if !strings.Contains(script, `iif "control" ip daddr {`) {
		t.Error("allowlist must drop private destinations")
	}
}

func TestFirewall_ShimNetAlwaysClosed(t *testing.T) {
	cfg := &Config{
		ShimCfg: &shimconfig.Config{UpstreamContainer: "x"},
		Networks: map[string]*NetworkSpec{
			"web": {Egress: "open"},
		},
	}
	script := renderFirewallScript(cfg)
	if !strings.Contains(script, `iif "shim-net" oif "shim-net" accept`) {
		t.Errorf("shim-net should emit intra-bridge accept; got:\n%s", script)
	}
	if strings.Contains(script, `iif "shim-net" ip daddr !`) {
		t.Error("shim-net must not get an egress-open rule")
	}
}

func TestAttachOrder_EgressFirstThenClosedThenShim(t *testing.T) {
	cfg := &Config{
		ShimCfg: &shimconfig.Config{UpstreamContainer: "api"},
		Networks: map[string]*NetworkSpec{
			"control":  {Egress: "allowlist", Allow: []string{"api.tinfoil.sh"}},
			"ipc-exec": {Egress: "closed"},
			"ipc-a":    {Egress: "closed"},
		},
	}
	c := Container{Name: "api", Networks: []string{"ipc-exec", "control", "ipc-a"}}
	first, rest := attachOrder(c, cfg)
	if first != "control" {
		t.Errorf("egress network should be first, got %q", first)
	}
	// shim-net must come last
	if len(rest) == 0 || rest[len(rest)-1] != "shim-net" {
		t.Errorf("shim-net should be last, got rest=%v", rest)
	}
}

func TestAttachOrder_NoNetworksNonShim(t *testing.T) {
	cfg := &Config{Networks: map[string]*NetworkSpec{}}
	c := Container{Name: "lonely"}
	first, rest := attachOrder(c, cfg)
	if first != "" || len(rest) != 0 {
		t.Errorf("unattached non-shim container should get nothing, got %q %v", first, rest)
	}
}

func TestAttachOrder_NoNetworksShimUpstreamGetsShimNet(t *testing.T) {
	cfg := &Config{
		ShimCfg:  &shimconfig.Config{UpstreamContainer: "upstream"},
		Networks: map[string]*NetworkSpec{},
	}
	c := Container{Name: "upstream"}
	first, rest := attachOrder(c, cfg)
	if first != "shim-net" {
		t.Errorf("upstream-with-no-networks should attach to shim-net, got %q", first)
	}
	if len(rest) != 0 {
		t.Errorf("expected no additional networks, got %v", rest)
	}
}
