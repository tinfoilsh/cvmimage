package firewall

import (
	"strings"
	"testing"
)

func TestInboundRulesTargetDedicatedChain(t *testing.T) {
	script, err := renderInboundScript([]int{80, 8443})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(script, "add rule inet tinfoil input ") {
		t.Fatalf("rules targeted parent input chain:\n%s", script)
	}
	for _, fragment := range []string{
		"flush chain inet tinfoil inbound",
		"add rule inet tinfoil inbound tcp dport 80 accept",
		"add rule inet tinfoil inbound tcp dport 8443 accept",
	} {
		if !strings.Contains(script, fragment) {
			t.Errorf("missing %q from:\n%s", fragment, script)
		}
	}
}
