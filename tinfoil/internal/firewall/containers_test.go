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
		`iif "closed" oif "closed" accept`,
		`iif "open" ip daddr != {`,
		"create set inet tinfoil allow-control",
		`iif "control" ip daddr @allow-control accept`,
	} {
		if !strings.Contains(script, fragment) {
			t.Errorf("missing %q from:\n%s", fragment, script)
		}
	}
}

func TestContainerNetworkPolicyKeepsShimClosed(t *testing.T) {
	config := &runtimeconfig.Config{
		ShimCfg:  &shimconfig.Config{UpstreamContainer: "api"},
		Networks: map[string]*runtimeconfig.NetworkSpec{},
	}
	script := renderContainerNetworkScript(config, false)
	if !strings.Contains(script, `iif "shim-net" oif "shim-net" accept`) || strings.Contains(script, `iif "shim-net" ip daddr !`) {
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
