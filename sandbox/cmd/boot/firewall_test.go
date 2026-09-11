package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMeasuredFirewallDefinesHTTP01Chain(t *testing.T) {
	policyPath := filepath.Join("..", "..", "rootfs", "etc", "nftables.conf")
	policy, err := os.ReadFile(policyPath)
	if err != nil {
		t.Fatalf("reading %s: %v", policyPath, err)
	}

	text := string(policy)
	for _, contract := range []string{
		"chain http01 {\n    }",
		"jump http01",
		"ip protocol 1 accept",
		"meta l4proto 58 accept",
	} {
		if !strings.Contains(text, contract) {
			t.Fatalf("measured firewall policy does not contain %q", contract)
		}
	}
	if strings.Contains(text, "tcp dport 80 accept") {
		t.Fatal("measured firewall policy opens HTTP-01 before certificate issuance")
	}
	for _, protocolName := range []string{"ip protocol icmp", "l4proto ipv6-icmp"} {
		if strings.Contains(text, protocolName) {
			t.Fatalf("measured firewall policy depends on protocol-name parsing: %q", protocolName)
		}
	}
}
