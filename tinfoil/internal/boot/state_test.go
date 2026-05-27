package boot

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteStateAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "boot-state.json")

	payload := []byte(`{"stages":[],"started_at":"2026-01-01T00:00:00Z"}`)
	if err := writeStateAtomic(path, payload); err != nil {
		t.Fatalf("writeStateAtomic: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("got %q, want %q", got, payload)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if e.Name() != "boot-state.json" {
			t.Fatalf("leftover temp file %q in state dir", e.Name())
		}
	}
}
