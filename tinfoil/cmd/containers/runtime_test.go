package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseInvocation(t *testing.T) {
	invocation, err := parseInvocation([]string{"tinfoil-containers", "--debug=true", "--secrets-fd=3"})
	if err != nil || !invocation.debug || invocation.secretsFD != 3 {
		t.Fatalf("parseInvocation() = %#v, %v", invocation, err)
	}
	if _, err := parseInvocation([]string{"tinfoil-containers", "unexpected"}); err == nil {
		t.Fatal("unexpected positional argument accepted")
	}
}

func TestReplacementPIDAvailableUsesFileGeneration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "service.pid")
	if err := os.WriteFile(path, []byte("41\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	previous, err := openServiceInstance(path)
	if err != nil {
		t.Fatal(err)
	}
	defer previous.close()
	if available, err := replacementPIDAvailable(path, previous); err != nil || available {
		t.Fatalf("old pid: available=%v error=%v", available, err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if available, err := replacementPIDAvailable(path, previous); err != nil || available {
		t.Fatalf("missing pid file: available=%v error=%v", available, err)
	}
	replacement := filepath.Join(filepath.Dir(path), "replacement.pid")
	if err := os.WriteFile(replacement, []byte("41\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, path); err != nil {
		t.Fatal(err)
	}
	if available, err := replacementPIDAvailable(path, previous); err != nil || !available {
		t.Fatalf("replacement pid: available=%v error=%v", available, err)
	}
}

func TestNetworkGenerationsNeverReuseConnectionMarks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "generation")
	first, err := nextNetworkGeneration(path, 3)
	if err != nil || first != 1 {
		t.Fatalf("first range starts at %d: %v", first, err)
	}
	next, err := nextNetworkGeneration(path, 2)
	if err != nil || next != 4 {
		t.Fatalf("replacement reused a connection mark: %d, %v", next, err)
	}
	for _, invalid := range []string{"", "0", "invalid", "4294967294", "4294967295"} {
		if err := os.WriteFile(path, []byte(invalid), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := nextNetworkGeneration(path, 2); err == nil {
			t.Fatalf("invalid or exhausted generation accepted: %q", invalid)
		}
	}
}
