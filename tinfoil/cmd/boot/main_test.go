package main

import (
	"testing"
)

func TestParseInvocation(t *testing.T) {
	invocation, err := parseInvocation([]string{"tinfoil-boot", "--secrets-fd=3"})
	if err != nil {
		t.Fatalf("normal boot invocation failed: %v", err)
	}
	if invocation.secretsFD != 3 {
		t.Fatalf("invocation = %#v", invocation)
	}
	if _, err := parseInvocation([]string{"tinfoil-boot", "--debug=true", "--secrets-fd=3"}); err == nil {
		t.Fatal("the removed debug switch was accepted")
	}

	for _, command := range []string{"containers", "models", "unknown"} {
		t.Run(command, func(t *testing.T) {
			if _, err := parseInvocation([]string{"tinfoil-boot", command}); err == nil {
				t.Fatalf("maintenance command %q was accepted", command)
			}
		})
	}
}
