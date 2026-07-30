package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseInvocation(t *testing.T) {
	debug, err := parseInvocation([]string{"tinfoil-containers", "--debug=true"})
	if err != nil || !debug {
		t.Fatalf("parseInvocation() = %t, %v", debug, err)
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
