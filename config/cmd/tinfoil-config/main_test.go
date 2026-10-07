package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Exercise a separately linked CLI process so digest support cannot be
// satisfied incidentally by imports in the Go test binary.
func TestStandaloneCLIValidatesImages(t *testing.T) {
	tempDir := t.TempDir()
	binary := filepath.Join(tempDir, "tinfoil-config")
	if output, err := exec.Command("go", "build", "-o", binary, ".").CombinedOutput(); err != nil {
		t.Fatalf("build CLI: %v\n%s", err, output)
	}
	for _, test := range []struct {
		name  string
		image string
		want  string
	}{
		{name: "SHA256 digest", image: "example.com/app@sha256:" + strings.Repeat("a", 64)},
		{name: "mutable tag", image: "example.com/app:latest", want: "immutable digest"},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := filepath.Join(t.TempDir(), "config.yml")
			data := []byte(fmt.Sprintf(`
cvm-version: 0.11.0
shim:
  upstream-port: 8080
containers:
  - name: app
    image: %s
`, test.image))
			if err := os.WriteFile(config, data, 0o600); err != nil {
				t.Fatal(err)
			}
			output, err := exec.Command(binary, config).CombinedOutput()
			if test.want != "" {
				var exitErr *exec.ExitError
				if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 {
					t.Fatalf("run CLI: %v, want exit code 1\n%s", err, output)
				}
				if !strings.Contains(string(output), test.want) {
					t.Fatalf("output = %q, want substring %q", output, test.want)
				}
				return
			}
			if err != nil {
				t.Fatalf("run CLI: %v\n%s", err, output)
			}
			if !strings.Contains(string(output), "valid tinfoil config: "+config) {
				t.Fatalf("missing validation result: %s", output)
			}
		})
	}
}
