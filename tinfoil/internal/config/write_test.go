package config

import (
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteShimPublishesCompleteConfigForBootAndReload(t *testing.T) {
	directory := t.TempDir()
	path, externalPath := filepath.Join(directory, "shim.yml"), filepath.Join(directory, "external.yml")
	if err := os.WriteFile(externalPath, []byte("env:\n  DOMAIN: localhost\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	config := &Config{
		TLSMode: "self-signed", TLSEnv: "production", TLSChallengeMode: "dns",
		UpstreamPort: 8080, Paths: []string{"/healthz"},
	}
	if err := WriteShim(path, config); err != nil {
		t.Fatal(err)
	}
	loaded, external, err := Load(path, externalPath)
	if err != nil || loaded.UpstreamPort != 8080 || loaded.TLSMode != "self-signed" || external.Env["DOMAIN"] != "localhost" {
		t.Fatalf("initial shim config: %#v, %#v, %v", loaded, external, err)
	}
	original, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer original.Close()
	before, err := io.ReadAll(original)
	if err != nil {
		t.Fatal(err)
	}
	config.UpstreamPort = 9000
	if err := WriteShim(path, config); err != nil {
		t.Fatal(err)
	}
	loaded, _, err = Load(path, externalPath)
	if err != nil || loaded.UpstreamPort != 9000 {
		t.Fatalf("reloaded shim config: %#v, %v", loaded, err)
	}
	if _, err := original.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	after, err := io.ReadAll(original)
	if err != nil || string(after) != string(before) {
		t.Fatalf("reload modified the file held by an existing reader: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("published config permissions: %v, %v", info, err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 2 {
		t.Fatalf("temporary files left after publication: %v, %v", entries, err)
	}
}
