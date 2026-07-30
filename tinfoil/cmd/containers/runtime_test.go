package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReplacementPIDAvailableWaitsThroughSupervisorBackoff(t *testing.T) {
	path := filepath.Join(t.TempDir(), "service.pid")
	if available, err := replacementPIDAvailable(path, 41); err != nil || available {
		t.Fatalf("missing pid file: available=%v error=%v", available, err)
	}
	if err := os.WriteFile(path, []byte("41\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if available, err := replacementPIDAvailable(path, 41); err != nil || available {
		t.Fatalf("old pid: available=%v error=%v", available, err)
	}
	if err := os.WriteFile(path, []byte("42\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if available, err := replacementPIDAvailable(path, 41); err != nil || !available {
		t.Fatalf("replacement pid: available=%v error=%v", available, err)
	}
}
