package device

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadDiskPayloadIsBoundedAndRequiresZeroPadding(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	if err := os.WriteFile(path, append([]byte("gpus: 0\n"), make([]byte, 32)...), 0644); err != nil {
		t.Fatal(err)
	}
	data, err := ReadDiskPayload(path, 16)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "gpus: 0\n" {
		t.Fatalf("payload = %q", data)
	}

	if err := os.WriteFile(path, []byte("valid\x00hidden"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadDiskPayload(path, 16); err == nil {
		t.Fatal("ReadDiskPayload accepted data after NUL padding")
	}

	if err := os.WriteFile(path, []byte(strings.Repeat("x", 17)), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadDiskPayload(path, 16); err == nil {
		t.Fatal("ReadDiskPayload accepted an oversized payload")
	}
}
