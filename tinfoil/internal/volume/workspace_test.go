package volume

import (
	"bytes"
	"crypto/sha512"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"golang.org/x/sys/unix"
	"tinfoil/internal/runtimeconfig"
)

func workspaceSpec() Spec {
	return Spec{VolumeSpec: runtimeconfig.VolumeSpec{Name: "workspace", Exec: true, Overlays: []runtimeconfig.VolumeOverlay{{Model: "nix", Source: "nix/store", Target: "store"}}}, Models: 1}
}

func TestWorkspaceValidation(t *testing.T) {
	if err := ValidateWorkspace(workspaceSpec()); err != nil {
		t.Fatal(err)
	}
	changes := []func(*Spec){
		func(s *Spec) { s.Index = 1 }, func(s *Spec) { s.Name = "another" },
		func(s *Spec) { s.Exec = false }, func(s *Spec) { s.Owner = 1000 },
		func(s *Spec) { s.KeySecret = "KEY" }, func(s *Spec) { s.Overlays = nil },
		func(s *Spec) { s.Overlays[0].Target = "other" },
		func(s *Spec) { s.Overlays[0].Model = "../escape" },
	}
	for i, change := range changes {
		s := workspaceSpec()
		change(&s)
		if ValidateWorkspace(s) == nil {
			t.Fatalf("accepted mutation %d", i)
		}
	}
}

func TestWorkspaceExportPrecedesOwnerSealAndUnwindsFailures(t *testing.T) {
	owner := "ssh-ed25519 canonical-owner\n"
	want := sha512.Sum384([]byte(owner))
	volumeIdentity, err := keySeal(bytes.Repeat([]byte{7}, KeyBytes))
	if err != nil {
		t.Fatal(err)
	}
	if volumeIdentity == want {
		t.Fatal("SSH owner seal equals volume-key seal")
	}
	for _, failure := range []string{"", WorkspacePath, NixPath, "seal"} {
		t.Run(failure, func(t *testing.T) {
			var mounted, removed []string
			sealed := false
			err := exportAndSeal("/data/workspace", owner,
				func(source, target, fs string, flags uintptr, data string) error {
					if source != "/data/workspace" || flags != unix.MS_BIND|unix.MS_REC || fs != "" || data != "" {
						t.Fatal("export contract changed")
					}
					if target == failure {
						return errors.New("mount failed")
					}
					mounted = append(mounted, target)
					return nil
				}, func(target string, flags int) error { removed = append(removed, target); return nil },
				func(digest []byte) error {
					if !reflect.DeepEqual(mounted, []string{WorkspacePath, NixPath}) {
						t.Fatal("sealed before exports")
					}
					if !bytes.Equal(digest, want[:]) {
						t.Fatal("seal does not bind canonical SSH owner")
					}
					if failure == "seal" {
						return errors.New("seal failed")
					}
					sealed = true
					return nil
				})
			if (err == nil) != (failure == "") || sealed != (failure == "") {
				t.Fatalf("sealed=%v error=%v", sealed, err)
			}
			if failure != "" {
				for i, target := range removed {
					if target != mounted[len(mounted)-1-i] {
						t.Fatal("exports removed out of order")
					}
				}
				if len(removed) != len(mounted) {
					t.Fatal("export leaked")
				}
			}
		})
	}
}

func TestPersistentWorkspaceLayoutReopensAndRejectsSymlinks(t *testing.T) {
	root := t.TempDir()
	if err := workspaceLayout(root, "nix"); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(root, "home", "saved")
	if err := os.WriteFile(marker, []byte("retained"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := workspaceLayout(root, "nix"); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(marker); err != nil || string(data) != "retained" {
		t.Fatal("workspace changed on reopen")
	}
	if err := os.RemoveAll(filepath.Join(root, "var")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(t.TempDir(), filepath.Join(root, "var")); err != nil {
		t.Fatal(err)
	}
	if err := workspaceLayout(root, "nix"); err == nil {
		t.Fatal("accepted persistent symlink")
	}
}
