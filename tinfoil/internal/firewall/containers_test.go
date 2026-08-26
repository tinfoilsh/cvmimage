package firewall

import (
	"strings"
	"testing"

	shimconfig "tinfoil/internal/config"
	"tinfoil/internal/runtimeconfig"
)

func mustRender(t *testing.T, config *runtimeconfig.Config, debug bool) string {
	t.Helper()
	script, err := renderContainerNetworkScript(config, debug)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	return script
}

func TestContainerNetworkPolicyModes(t *testing.T) {
	config := &runtimeconfig.Config{Networks: map[string]*runtimeconfig.NetworkSpec{
		"closed":  {Egress: "closed"},
		"open":    {Egress: "open"},
		"control": {Egress: "allowlist"},
	}}
	script := mustRender(t, config, false)
	for _, fragment := range []string{
		"flush chain inet tinfoil container_input",
		"flush chain inet tinfoil container_forward",
		`iifname "closed" oifname "closed" accept`,
		`iifname "open" ip daddr { 0.0.0.0/8`,
		`iifname "open" meta nfproto ipv4 accept`,
		`iifname "open" meta nfproto ipv6 accept`,
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
	script := mustRender(t, config, false)
	drop := strings.Index(script, `ip daddr { 0.0.0.0/8`)
	accept := strings.Index(script, `iifname "open" meta nfproto ipv4 accept`)
	if drop < 0 || accept < 0 || drop > accept || strings.Contains(script, "192.0.0.9") || strings.Contains(script, "192.0.0.10") {
		t.Fatalf("unexpected open IPv4 rule order:\n%s", script)
	}
}

func TestContainerNetworkPolicyKeepsShimClosed(t *testing.T) {
	config := &runtimeconfig.Config{
		ShimCfg:  &shimconfig.Config{UpstreamContainer: "api"},
		Networks: map[string]*runtimeconfig.NetworkSpec{},
	}
	script := mustRender(t, config, false)
	if !strings.Contains(script, `iifname "shim-net" oifname "shim-net" accept`) || strings.Contains(script, `iifname "shim-net" ip daddr !`) {
		t.Fatalf("unexpected shim policy:\n%s", script)
	}
}

func TestContainerNetworkPolicyDebugForwarding(t *testing.T) {
	config := &runtimeconfig.Config{Containers: []runtimeconfig.Container{{Name: runtimeconfig.ReservedDebugContainerName}}}
	if script := mustRender(t, config, true); !strings.Contains(script, `oifname "docker0" ct status dnat tcp dport 2222 accept`) {
		t.Fatalf("debug forwarding missing:\n%s", script)
	}
	if script := mustRender(t, config, false); strings.Contains(script, "docker0") {
		t.Fatalf("production policy opened docker0:\n%s", script)
	}
}

func TestContainerNetworkPolicyPublishedPorts(t *testing.T) {
	config := &runtimeconfig.Config{
		Networks: map[string]*runtimeconfig.NetworkSpec{
			"app":     {Egress: "closed"},
			"unused":  {Egress: "closed"},
			"control": {Egress: "open"},
		},
		Containers: []runtimeconfig.Container{{
			Name: "sandbox",
			// Docker publishes on the primary network, which AttachOrder
			// puts at the egress-capable one regardless of listing order.
			Networks: []string{"app", "control"},
			Ports:    []string{"2022:22", "8443:8443"},
		}},
	}
	script := mustRender(t, config, false)
	for _, fragment := range []string{
		`oifname "control" ct status dnat tcp dport 22 accept`,
		`oifname "control" ct status dnat tcp dport 8443 accept`,
		`iifname "control" ct state established,related accept`,
	} {
		if !strings.Contains(script, fragment) {
			t.Errorf("missing %q from:\n%s", fragment, script)
		}
	}
	for _, fragment := range []string{
		`oifname "app" ct status dnat`,
		`oifname "unused" ct status dnat`,
		`iifname "unused" ct state established,related accept`,
	} {
		if strings.Contains(script, fragment) {
			t.Errorf("unexpected %q in:\n%s", fragment, script)
		}
	}
	// The reply leg must outrank the egress policy's private-range drop, or a
	// caller reaching the port from a private address never gets an answer.
	reply := strings.Index(script, `iifname "control" ct state established,related accept`)
	drop := strings.Index(script, `iifname "control" ip daddr {`)
	if reply < 0 || drop < 0 || reply > drop {
		t.Fatalf("published reply leg must precede the private-range drop:\n%s", script)
	}
}

func TestContainerNetworkPolicyIgnoresPortsWithoutNetwork(t *testing.T) {
	config := &runtimeconfig.Config{
		Networks: map[string]*runtimeconfig.NetworkSpec{"app": {Egress: "closed"}},
		Containers: []runtimeconfig.Container{{
			Name:  "stranded",
			Ports: []string{"2022:22"},
		}},
	}
	if script := mustRender(t, config, false); strings.Contains(script, "ct status dnat") {
		t.Fatalf("unattached container opened a bridge:\n%s", script)
	}
}
