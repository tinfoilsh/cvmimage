package main

import (
	"testing"
)

func TestParseInvocation(t *testing.T) {
	invocation, err := parseInvocation([]string{"tinfoil-boot", "--config-hash=abc", "--debug=true"})
	if err != nil {
		t.Fatalf("normal boot invocation failed: %v", err)
	}
	if invocation.configHash != "abc" || !invocation.debug {
		t.Fatalf("invocation = %#v", invocation)
	}

	for _, command := range []string{"containers", "models", "unknown"} {
		t.Run(command, func(t *testing.T) {
			if _, err := parseInvocation([]string{"tinfoil-boot", command}); err == nil {
				t.Fatalf("maintenance command %q was accepted", command)
			}
		})
	}
}
