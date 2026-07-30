package firewall

import (
	"strings"
	"testing"

	shimconfig "tinfoil/internal/config"
	"tinfoil/internal/runtimeconfig"
)

func TestContainerNetworkPolicyModes(t *testing.T) {
	config := &runtimeconfig.Config{Networks: map[string]*runtimeconfig.NetworkSpec{
		"closed":  {Egress: "closed"},
		"open":    {Egress: "open"},
		"control": {Egress: "allowlist"},
	}}
	script := renderContainerNetworkScript(config, false)
	for _, fragment := range []string{
		"flush chain inet tinfoil container_input",
		"flush chain inet tinfoil container_forward",
		`iifname "closed" oifname "closed" accept`,
		`iifname "open" ip daddr { 0.0.0.0/8`,
		`iifname "open" ip accept`,
		"destroy set inet tinfoil allow-control",
		"create set inet tinfoil allow-control",
		`iifname "control" ip daddr @allow-control accept`,
	} {
		if !strings.Contains(script, fragment) {
			t.Errorf("missing %q from:\n%s", fragment, script)
		}
	}
	destroy := strings.Index(script, "destroy set inet tinfoil allow-control")
	create := strings.Index(script, "create set inet tinfoil allow-control")
	if destroy < 0 || create < 0 || destroy > create {
		t.Fatalf("allowlist set must be replaced before use:\n%s", script)
	}
	accept := strings.Index(script, `iifname "control" ip daddr @allow-control accept`)
	drop := strings.Index(script, `iifname "control" ip daddr {`)
	if accept < 0 || drop < 0 || accept > drop {
		t.Fatalf("allowlist accept must precede private-range drop:\n%s", script)
	}
}

func TestOpenEgressRejectsProtocolAssignments(t *testing.T) {
	config := &runtimeconfig.Config{Networks: map[string]*runtimeconfig.NetworkSpec{
		"open": {Egress: "open"},
	}}
	script := renderContainerNetworkScript(config, false)
	drop := strings.Index(script, `ip daddr { 0.0.0.0/8`)
	accept := strings.Index(script, `iifname "open" ip accept`)
	if drop < 0 || accept < 0 || drop > accept || strings.Contains(script, "192.0.0.9") || strings.Contains(script, "192.0.0.10") {
		t.Fatalf("unexpected open IPv4 rule order:\n%s", script)
	}
}

func TestContainerNetworkPolicyKeepsShimClosed(t *testing.T) {
	config := &runtimeconfig.Config{
		ShimCfg:  &shimconfig.Config{UpstreamContainer: "api"},
		Networks: map[string]*runtimeconfig.NetworkSpec{},
	}
	script := renderContainerNetworkScript(config, false)
	if !strings.Contains(script, `iifname "shim-net" oifname "shim-net" accept`) || strings.Contains(script, `iifname "shim-net" ip daddr !`) {
		t.Fatalf("unexpected shim policy:\n%s", script)
	}
}

func TestContainerNetworkPolicyDebugForwarding(t *testing.T) {
	config := &runtimeconfig.Config{Containers: []runtimeconfig.Container{{Name: runtimeconfig.ReservedDebugContainerName}}}
	if script := renderContainerNetworkScript(config, true); !strings.Contains(script, `oifname "docker0" ct status dnat tcp dport 2222 accept`) {
		t.Fatalf("debug forwarding missing:\n%s", script)
	}
	if script := renderContainerNetworkScript(config, false); strings.Contains(script, "docker0") {
		t.Fatalf("production policy opened docker0:\n%s", script)
	}
}
