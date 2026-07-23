package main

import (
	"testing"
)

func TestValidateInvocation(t *testing.T) {
	if err := validateInvocation([]string{"tinfoil-boot"}); err != nil {
		t.Fatalf("normal boot invocation failed: %v", err)
	}

	for _, command := range []string{"containers", "models", "unknown"} {
		t.Run(command, func(t *testing.T) {
			if err := validateInvocation([]string{"tinfoil-boot", command}); err == nil {
				t.Fatalf("maintenance command %q was accepted", command)
			}
		})
	}
}
