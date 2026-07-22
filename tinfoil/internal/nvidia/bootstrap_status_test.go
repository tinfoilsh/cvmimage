package nvidia

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBootstrapStatusExactEncodingsRoundTrip(t *testing.T) {
	tests := []struct {
		name    string
		status  BootstrapStatus
		encoded string
	}{
		{name: "no-gpu", status: NoGPUBootstrapStatus(), encoded: "tinfoil-nvidia-bootstrap-v1:no-gpu\n"},
		{name: "failed", status: FailedBootstrapStatus(), encoded: "tinfoil-nvidia-bootstrap-v1:failed\n"},
		{name: "ready-one", status: ReadyBootstrapStatus(1), encoded: "tinfoil-nvidia-bootstrap-v1:ready:1\n"},
		{name: "ready-eight", status: ReadyBootstrapStatus(8), encoded: "tinfoil-nvidia-bootstrap-v1:ready:8\n"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "run", "status")
			if err := WriteBootstrapStatus(path, test.status); err != nil {
				t.Fatal(err)
			}
			encoded, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if string(encoded) != test.encoded {
				t.Fatalf("encoding = %q, want %q", encoded, test.encoded)
			}
			got, err := ReadBootstrapStatus(path)
			if err != nil {
				t.Fatal(err)
			}
			if got != test.status {
				t.Fatalf("status = %#v, want %#v", got, test.status)
			}
		})
	}
}

func TestWriteBootstrapStatusAtomicallyReplacesSymlink(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "status")
	victim := filepath.Join(directory, "victim")
	if err := os.WriteFile(victim, []byte("unchanged"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, path); err != nil {
		t.Fatal(err)
	}
	if err := WriteBootstrapStatus(path, NoGPUBootstrapStatus()); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() {
		t.Fatalf("published status mode = %s", info.Mode())
	}
	contents, err := os.ReadFile(victim)
	if err != nil {
		t.Fatal(err)
	}
	if string(contents) != "unchanged" {
		t.Fatalf("symlink target changed to %q", contents)
	}
}

func TestReadBootstrapStatusFailsClosed(t *testing.T) {
	directory := t.TempDir()
	regular := filepath.Join(directory, "regular")
	if err := os.WriteFile(regular, bootstrapNoGPU, 0600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(directory, "symlink")
	if err := os.Symlink(regular, symlink); err != nil {
		t.Fatal(err)
	}
	malformed := filepath.Join(directory, "malformed")
	if err := os.WriteFile(malformed, []byte("tinfoil-nvidia-bootstrap-v1:ready:01\n"), 0600); err != nil {
		t.Fatal(err)
	}
	oversized := filepath.Join(directory, "oversized")
	if err := os.WriteFile(oversized, []byte(strings.Repeat("x", maxBootstrapStatusSize+1)), 0600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		filepath.Join(directory, "missing"),
		malformed,
		symlink,
		oversized,
		directory,
	} {
		if _, err := ReadBootstrapStatus(path); err == nil {
			t.Fatalf("ReadBootstrapStatus(%q) succeeded", path)
		}
	}
}

func TestValidateBootstrapStatusRequiresExactConfigMatch(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "status")
	tests := []struct {
		name       string
		status     BootstrapStatus
		configured int
		wantErr    bool
	}{
		{name: "no-gpu", status: NoGPUBootstrapStatus(), configured: 0},
		{name: "ready", status: ReadyBootstrapStatus(8), configured: 8},
		{name: "failed", status: FailedBootstrapStatus(), configured: 8, wantErr: true},
		{name: "no-gpu-configured", status: NoGPUBootstrapStatus(), configured: 1, wantErr: true},
		{name: "ready-config-zero", status: ReadyBootstrapStatus(1), configured: 0, wantErr: true},
		{name: "ready-count-mismatch", status: ReadyBootstrapStatus(8), configured: 1, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := WriteBootstrapStatus(path, test.status); err != nil {
				t.Fatal(err)
			}
			err := ValidateBootstrapStatus(path, test.configured)
			if (err != nil) != test.wantErr {
				t.Fatalf("ValidateBootstrapStatus() error = %v, wantErr %v", err, test.wantErr)
			}
		})
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	if err := ValidateBootstrapStatus(path, 0); err == nil {
		t.Fatal("missing status succeeded")
	}
}

func TestWriteBootstrapStatusRejectsInvalidStates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "status")
	for _, status := range []BootstrapStatus{
		{},
		ReadyBootstrapStatus(0),
		ReadyBootstrapStatus(9),
		{State: BootstrapStateNoGPU, GPUCount: 1},
		{State: BootstrapStateFailed, GPUCount: 1},
	} {
		if err := WriteBootstrapStatus(path, status); err == nil {
			t.Fatalf("WriteBootstrapStatus(%#v) succeeded", status)
		}
	}
}
