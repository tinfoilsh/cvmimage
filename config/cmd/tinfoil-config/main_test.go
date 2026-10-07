package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// Exercise a separately linked CLI process so digest support cannot be
// satisfied incidentally by imports in the Go test binary.
func TestStandaloneCLIValidatesSHA256Image(t *testing.T) {
	tempDir := t.TempDir()
	binary := filepath.Join(tempDir, "tinfoil-config")
	if output, err := exec.Command("go", "build", "-o", binary, ".").CombinedOutput(); err != nil {
		t.Fatalf("build CLI: %v\n%s", err, output)
	}
	config := filepath.Join(tempDir, "config.yml")
	data := []byte(`
cvm-version: 0.11.0
shim:
  upstream-port: 8080
containers:
  - name: app
    image: example.com/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
`)
	if err := os.WriteFile(config, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command(binary, config).CombinedOutput(); err != nil {
		t.Fatalf("run CLI: %v\n%s", err, output)
	}
}
