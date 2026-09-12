package volume

import (
	"errors"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// Overlay directories retain the persistent layout used by existing volumes.
const (
	upperSuffix = ".upper"
	workSuffix  = ".work"
)

// overlay adds a writable view of a verified lower directory to this tree.
// Root owns the upper and work directories; owner owns the merged view.
func (t *mountTree) overlay(lower, relative string, owner int) error {
	if t.closing || len(t.mounts) == 0 {
		return errors.New("mount tree is closed")
	}
	if len(t.exports) != 0 {
		return errors.New("cannot add overlays to an exported mount tree")
	}
	resolved, err := filepath.EvalSymlinks(lower)
	if err != nil {
		return err
	}
	if resolved != lower {
		return errors.New("overlay lower must be a real path")
	}
	for _, path := range []string{relative, relative + upperSuffix, relative + workSuffix} {
		if err := ensureDirectory(t.root, path, 0755); err != nil {
			return err
		}
	}
	target := filepath.Join(t.root, relative)
	flags := uintptr(unix.MS_NODEV | unix.MS_NOSUID)
	if !t.executable {
		flags |= unix.MS_NOEXEC
	}
	options := "lowerdir=" + lower + ",upperdir=" + target + upperSuffix + ",workdir=" + target + workSuffix
	if err := t.kernel.mount("overlay", target, "overlay", flags, options); err != nil {
		return err
	}
	t.mounts = append(t.mounts, target)
	return t.kernel.chown(target, owner, owner)
}
