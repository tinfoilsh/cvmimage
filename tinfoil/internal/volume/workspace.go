package volume

import (
	"context"
	"crypto/sha512"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
	"tinfoil/internal/boot"
)

const WorkspacePath = "/workspace"
const NixPath = "/nix"
const PackProfile = "nix/var/nix/profiles/default"

// ValidateWorkspace restricts the first sandbox release to one root-owned,
// executable workspace with a single toolchain store overlay.
func ValidateWorkspace(spec Spec) error {
	if err := spec.Validate(); err != nil {
		return err
	}
	if spec.Index != 0 || spec.Name != "workspace" || spec.Owner != 0 || !spec.Exec || spec.KeySecret != "" {
		return errors.New("workspace must be the first root-owned executable volume and use an enrollment key")
	}
	if len(spec.Overlays) != 1 || spec.Overlays[0].Source != "nix/store" || spec.Overlays[0].Target != "store" {
		return errors.New("workspace requires one nix/store overlay at store")
	}
	return nil
}

// OpenWorkspace uses the same authenticated disk format and formatter as Mount.
// owner is the canonical authorized-key line accepted by enrollment, including
// its trailing newline. Unlike runtime unlock, enrollment seals to this SSH
// owner rather than to an identity derived from the volume key.
func OpenWorkspace(ctx context.Context, spec Spec, key []byte, owner string) error {
	if err := ValidateWorkspace(spec); err != nil {
		return err
	}
	if len(key) != KeyBytes {
		return fmt.Errorf("key is %d bytes, want %d", len(key), KeyBytes)
	}
	if strings.TrimSpace(owner) == "" {
		return errors.New("workspace owner is required")
	}
	for _, target := range []string{WorkspacePath, NixPath} {
		info, err := os.Lstat(target)
		if err != nil {
			return err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("workspace export %s is not a directory", target)
		}
		state, parent, err := mountStates(target)
		if err != nil {
			return err
		}
		if state.id != parent.id {
			return fmt.Errorf("workspace export %s is already mounted", target)
		}
	}
	instance, err := openVolume(spec)
	if err != nil {
		return err
	}
	defer instance.closeDevices()
	mounted, err := instance.prepare()
	if err != nil {
		return err
	}
	if mounted {
		return errors.New("workspace is already open")
	}
	blank, err := blockDeviceBlank(instance.source)
	if err != nil {
		return err
	}
	return instance.activateWith(ctx, key, blank, func() error {
		if err := workspaceLayout(instance.dataPath(), spec.Overlays[0].Model); err != nil {
			return err
		}
		return exportAndSeal(instance.dataPath(), owner, unix.Mount, unix.Unmount, extendSeal)
	})
}

// Check every persistent directory before using it. An owner's previous session
// may have replaced any of these paths with a symlink.
func workspaceLayout(root, model string) error {
	for _, relative := range []string{"home", "var", "var/nix", "var/nix/profiles"} {
		path := filepath.Join(root, relative)
		if err := os.Mkdir(path, 0o755); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("workspace path %s is not a directory", path)
		}
	}
	target := filepath.Join(boot.PrivateModelsDir, model, PackProfile)
	profile := filepath.Join(root, "var/nix/profiles/default")
	if err := os.Symlink(target, profile); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return err
		}
		existing, err := os.Readlink(profile)
		if err != nil || existing != target {
			return fmt.Errorf("workspace profile does not reference the measured toolchain")
		}
	}
	return nil
}

func exportAndSeal(source, owner string, mount func(string, string, string, uintptr, string) error, unmount func(string, int) error, extend func([]byte) error) (result error) {
	var mounted []string
	defer func() {
		if result != nil {
			for i := len(mounted) - 1; i >= 0; i-- {
				result = errors.Join(result, unmount(mounted[i], unix.MNT_DETACH))
			}
		}
	}()
	for _, target := range []string{WorkspacePath, NixPath} {
		if err := mount(source, target, "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
			return fmt.Errorf("exporting workspace at %s: %w", target, err)
		}
		mounted = append(mounted, target)
	}
	digest := sha512.Sum384([]byte(owner))
	return extend(digest[:])
}
