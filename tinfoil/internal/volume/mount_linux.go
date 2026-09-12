package volume

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

type mountKernel interface {
	mount(string, string, string, uintptr, string) error
	unmount(string) error
	chown(string, int, int) error
	mountState(string) (mountState, error)
}

type linuxMountKernel struct{}

func (linuxMountKernel) mount(source, target, fs string, flags uintptr, data string) error {
	return unix.Mount(source, target, fs, flags, data)
}
func (linuxMountKernel) unmount(target string) error { return unix.Unmount(target, 0) }
func (linuxMountKernel) chown(target string, uid, gid int) error {
	return os.Chown(target, uid, gid)
}
func (linuxMountKernel) mountState(path string) (mountState, error) { return readMountState(path) }

// mountTree owns a base filesystem, its overlays, and recursive exports. Add overlays
// before exporting the tree so each export contains the complete mount layout.
type mountTree struct {
	kernel     mountKernel
	root       string
	executable bool
	mounts     []string
	exports    []string
	closing    bool
}

// Close releases exports, overlays, and the base mount, stopping at a busy mount.
// Successful steps are forgotten so the caller can retry failed cleanup.
func (t *mountTree) Close() error {
	t.closing = true
	if err := t.unmount(&t.exports); err != nil {
		return err
	}
	return t.unmount(&t.mounts)
}

func (t *mountTree) unmount(paths *[]string) error {
	for len(*paths) > 0 {
		last := len(*paths) - 1
		if err := t.kernel.unmount((*paths)[last]); err != nil {
			return err
		}
		*paths = (*paths)[:last]
	}
	return nil
}

// prepareTarget creates a private mount directory and rejects an existing mount.
func prepareTarget(target string) error {
	if err := os.MkdirAll(target, 0700); err != nil {
		return err
	}
	return requireUnmounted(linuxMountKernel{}, target)
}

// mountDevice returns ownership as soon as the mount succeeds. The caller must
// close any returned tree, including one returned alongside an inspection error.
func mountDevice(kernel mountKernel, source string, number uint64, d Definition) (*mountTree, error) {
	flags, data, err := mountOptions(source, d.Filesystem, d.Access, d.Exec)
	if err != nil {
		return nil, err
	}
	if err := kernel.mount(source, d.Target, d.Filesystem, flags, data); err != nil {
		return nil, err
	}
	owned := &mountTree{kernel: kernel, root: d.Target, executable: d.Exec, mounts: []string{d.Target}}
	state, err := kernel.mountState(d.Target)
	if err != nil {
		return owned, err
	}
	if state.device != number {
		return owned, fmt.Errorf("mounted unexpected device %d:%d", unix.Major(state.device), unix.Minor(state.device))
	}
	return owned, nil
}

// export recursively binds this tree and retains all cloned mounts for cleanup.
func (t *mountTree) export(target string) error {
	if t.closing || len(t.mounts) == 0 {
		return errors.New("mount tree is closed")
	}
	if err := requireUnmounted(t.kernel, target); err != nil {
		return err
	}
	clones := []string{target}
	for _, child := range t.mounts[1:] {
		relative, err := filepath.Rel(t.root, child)
		if err != nil {
			return err
		}
		clones = append(clones, filepath.Join(target, relative))
	}
	if err := t.kernel.mount(t.root, target, "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
		return err
	}
	t.exports = append(t.exports, clones...)
	return nil
}

type mountState struct {
	id     uint64
	device uint64
}

func requireUnmounted(kernel mountKernel, target string) error {
	state, err := kernel.mountState(target)
	if err != nil {
		return err
	}
	parent, err := kernel.mountState(filepath.Dir(target))
	if err != nil {
		return err
	}
	if state.id != parent.id {
		return fmt.Errorf("target %s is already mounted", target)
	}
	return nil
}

func readMountState(path string) (mountState, error) {
	var info unix.Statx_t
	mask := unix.STATX_BASIC_STATS | unix.STATX_MNT_ID
	if err := unix.Statx(unix.AT_FDCWD, path, unix.AT_SYMLINK_NOFOLLOW, mask, &info); err != nil {
		return mountState{}, err
	}
	if info.Mask&unix.STATX_MNT_ID == 0 {
		return mountState{}, errors.New("kernel omitted mount ID")
	}
	return mountState{id: info.Mnt_id, device: unix.Mkdev(info.Dev_major, info.Dev_minor)}, nil
}
