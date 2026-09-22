package firewall

import (
	"strings"
	"testing"

	shimconfig "tinfoil/internal/config"
	"tinfoil/internal/runtimeconfig"
)

const dnatDrop = "add rule inet tinfoil container_forward ct status dnat drop"

func mustContainerScript(t *testing.T, config *runtimeconfig.Config, debug bool) string {
	t.Helper()
	script, err := renderContainerNetworkScript(config, debug)
	if err != nil {
		t.Fatal(err)
	}
	return script
}

func TestAdminSSHForwardPrecedesDNATDrop(t *testing.T) {
	cfg := &runtimeconfig.Config{
		CVMNetwork: runtimeconfig.CVMNetworkConfig{InboundPorts: []int{22}},
		Networks:   map[string]*runtimeconfig.NetworkSpec{"dev": {Egress: "closed"}},
		Containers: []runtimeconfig.Container{{Name: "workspace", CVMAdmin: true, Networks: []string{"dev"}, Ports: []string{"22:22", "3000:3000"}}},
	}
	script := mustContainerScript(t, cfg, false)
	accept := strings.Index(script, `oifname "dev" ct status dnat ct original proto-dst 22 tcp dport 22 accept`)
	reply := strings.Index(script, `iifname "dev" ct status dnat ct direction reply ct original proto-dst 22 ct state established,related accept`)
	drop := strings.Index(script, dnatDrop)
	if accept < 0 || reply < 0 || accept > drop || reply > drop || strings.Contains(script, "dport 3000") {
		t.Fatalf("SSH accept must precede the DNAT drop and open nothing else:\n%s", script)
	}
	if strings.Contains(mustContainerScript(t, cfg, true), "proto-dst 22") {
		t.Fatal("debug profile must not expose production SSH")
	}
	cfg.CVMNetwork.InboundPorts = nil
	if strings.Contains(mustContainerScript(t, cfg, false), "proto-dst 22") {
		t.Fatal("SSH exposed without the inbound-ports opt-in")
	}
}

func TestContainerNetworkPolicyModes(t *testing.T) {
	config := &runtimeconfig.Config{Networks: map[string]*runtimeconfig.NetworkSpec{
		"closed":  {Egress: "closed"},
		"open":    {Egress: "open"},
		"control": {Egress: "allowlist"},
	}}
	script := mustContainerScript(t, config, false)
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
	script := mustContainerScript(t, config, false)
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
	script := mustContainerScript(t, config, false)
	if !strings.Contains(script, `iifname "shim-net" oifname "shim-net" accept`) || strings.Contains(script, `iifname "shim-net" ip daddr !`) {
		t.Fatalf("unexpected shim policy:\n%s", script)
	}
}

func TestContainerNetworkPolicyDebugForwarding(t *testing.T) {
	config := &runtimeconfig.Config{Containers: []runtimeconfig.Container{{Name: runtimeconfig.ReservedDebugContainerName}}}
	script := mustContainerScript(t, config, true)
	toolbox := strings.Index(script, `oifname "docker0" ct status dnat tcp dport 2222 accept`)
	reply := strings.Index(script, `iifname "docker0" ct state established,related accept`)
	drop := strings.Index(script, dnatDrop)
	if toolbox < 0 || reply < 0 || drop < 0 || toolbox > reply || reply > drop {
		t.Fatalf("toolbox accept must outrank the dnat drop:\n%s", script)
	}
	if script := mustContainerScript(t, config, false); strings.Contains(script, "docker0") {
		t.Fatalf("production policy opened docker0:\n%s", script)
	}
}

func TestContainerNetworkPolicyDropsPublishedPorts(t *testing.T) {
	config := &runtimeconfig.Config{
		Networks:   map[string]*runtimeconfig.NetworkSpec{"app": {Egress: "closed"}},
		Containers: []runtimeconfig.Container{{Name: "sandbox", Networks: []string{"app"}, Ports: []string{"2022:22"}}},
	}
	script := mustContainerScript(t, config, false)
	if drop, bridge := strings.Index(script, dnatDrop), strings.Index(script, `container_forward iifname "app"`); drop < 0 || drop > bridge {
		t.Fatalf("dnat drop must precede the per-bridge rules:\n%s", script)
	}
}
