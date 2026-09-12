package volume

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"golang.org/x/sys/unix"
)

type fakeMountKernel struct {
	events    []string
	failMount string
	busy      string
	failChown bool
	state     mountState
	states    map[string]mountState
	statErr   error
	mounts    []mountCall
}

type mountCall struct {
	source, target, fs string
	flags              uintptr
	data               string
}

func (k *fakeMountKernel) mount(source, target, fs string, flags uintptr, data string) error {
	k.mounts = append(k.mounts, mountCall{source, target, fs, flags, data})
	k.events = append(k.events, "mount:"+target)
	if target == k.failMount {
		return errors.New("mount failed")
	}
	return nil
}
func (k *fakeMountKernel) unmount(target string) error {
	k.events = append(k.events, "unmount:"+target)
	if k.busy == target {
		return errors.New("busy")
	}
	return nil
}
func (k *fakeMountKernel) chown(target string, _, _ int) error {
	k.events = append(k.events, "chown:"+target)
	if k.failChown {
		return errors.New("chown failed")
	}
	return nil
}
func (k *fakeMountKernel) mountState(path string) (mountState, error) {
	if k.states != nil {
		return k.states[path], k.statErr
	}
	return k.state, k.statErr
}

func TestDeviceMountOwnsCleanupBeforeInspection(t *testing.T) {
	for _, failure := range []string{"", "mount", "inspect", "device", "busy"} {
		t.Run(failure, func(t *testing.T) {
			target := t.TempDir()
			k := &fakeMountKernel{state: mountState{device: 7}}
			switch failure {
			case "mount":
				k.failMount = target
			case "inspect":
				k.statErr = errors.New("statx failed")
			case "device":
				k.state.device = 8
			case "busy":
				k.busy = target
			}
			owned, err := mountDevice(k, "/dev/verified", 7, Definition{Target: target, Filesystem: "erofs", Access: "ro"})
			wantError := failure == "mount" || failure == "inspect" || failure == "device"
			if (err != nil) != wantError {
				t.Fatalf("mount: %v", err)
			}
			call := k.mounts[0]
			if call.source != "/dev/verified" || call.target != target || call.fs != "erofs" || call.flags != unix.MS_RDONLY|unix.MS_NODEV|unix.MS_NOSUID|unix.MS_NOEXEC || call.data != "" {
				t.Fatalf("unexpected mount: %+v", call)
			}
			if failure == "mount" {
				if owned != nil {
					t.Fatal("failed mount returned a handle")
				}
				return
			}
			if owned == nil {
				t.Fatal("lost mount after inspection")
			}
			k.events = nil
			if err := owned.Close(); failure == "busy" {
				if err == nil {
					t.Fatal("ignored busy mount")
				}
				k.busy = ""
				k.events = nil
				if err := owned.Close(); err != nil {
					t.Fatal(err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			want := []string{"unmount:" + target}
			if !slices.Equal(k.events, want) {
				t.Fatal(k.events)
			}
			if err := owned.Close(); err != nil || !slices.Equal(k.events, want) {
				t.Fatal("repeated completed cleanup")
			}
		})
	}
}

func TestFilesystemRejectionDoesNotMount(t *testing.T) {
	k := &fakeMountKernel{}
	device := filepath.Join(t.TempDir(), "dirty-ext4")
	if err := os.WriteFile(device, make([]byte, 2048), 0600); err != nil {
		t.Fatal(err)
	}
	owned, err := mountDevice(k, device, 7, Definition{Target: t.TempDir(), Filesystem: "ext4", Access: "ro"})
	if err == nil || owned != nil {
		t.Fatal("accepted invalid filesystem")
	}
	if len(k.mounts) != 0 {
		t.Fatal("mounted before checking filesystem")
	}
}

func testTree(t *testing.T, k *fakeMountKernel, executable bool) *mountTree {
	t.Helper()
	tree, err := mountDevice(k, "/dev/verified", 0, Definition{Target: t.TempDir(), Filesystem: "ext4", Access: "rw", Exec: executable})
	if err != nil {
		t.Fatal(err)
	}
	return tree
}

func TestTreeCleanupResumesAtBusyExportChild(t *testing.T) {
	k := &fakeMountKernel{}
	tree := testTree(t, k, false)
	for _, relative := range []string{"store", "cache"} {
		if err := tree.overlay(t.TempDir(), relative, 1000); err != nil {
			t.Fatal(err)
		}
	}
	first, second := t.TempDir(), t.TempDir()
	for _, target := range []string{first, second} {
		if err := tree.export(target); err != nil {
			t.Fatal(err)
		}
		call := k.mounts[len(k.mounts)-1]
		if call.source != tree.root || call.target != target || call.flags != unix.MS_BIND|unix.MS_REC {
			t.Fatal(call)
		}
	}
	k.events = nil
	k.busy = filepath.Join(first, "store")
	if err := tree.Close(); err == nil {
		t.Fatal("expected busy cloned overlay")
	}
	want := []string{
		"unmount:" + filepath.Join(second, "cache"), "unmount:" + filepath.Join(second, "store"), "unmount:" + second,
		"unmount:" + filepath.Join(first, "cache"), "unmount:" + k.busy,
	}
	if !slices.Equal(k.events, want) {
		t.Fatal(k.events)
	}
	k.busy = ""
	if err := tree.Close(); err != nil {
		t.Fatal(err)
	}
	want = append(want, "unmount:"+filepath.Join(first, "store"), "unmount:"+first,
		"unmount:"+filepath.Join(tree.root, "cache"), "unmount:"+filepath.Join(tree.root, "store"), "unmount:"+tree.root)
	if !slices.Equal(k.events, want) {
		t.Fatal(k.events)
	}
	if err := tree.Close(); err != nil || !slices.Equal(k.events, want) {
		t.Fatal("repeated completed cleanup")
	}
}

func TestExportRejectsAnExistingMount(t *testing.T) {
	target := t.TempDir()
	k := &fakeMountKernel{states: map[string]mountState{target: {id: 1}}}
	tree := testTree(t, k, false)
	k.mounts = nil
	if err := tree.export(target); err == nil || len(k.mounts) != 0 {
		t.Fatalf("mounted over an existing mount: %v, %v", k.mounts, err)
	}
	if err := tree.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestOverlayMountIsOwnedBeforeChown(t *testing.T) {
	lower := t.TempDir()
	k := &fakeMountKernel{failChown: true}
	tree := testTree(t, k, false)
	k.events, k.mounts = nil, nil
	if err := tree.overlay(lower, "store", 1000); err == nil {
		t.Fatal("lost overlay after ownership failure")
	}
	target := filepath.Join(tree.root, "store")
	call := k.mounts[0]
	wantOptions := "lowerdir=" + lower + ",upperdir=" + target + ".upper,workdir=" + target + ".work"
	if call.fs != "overlay" || call.data != wantOptions || call.flags != unix.MS_NODEV|unix.MS_NOSUID|unix.MS_NOEXEC {
		t.Fatal(call)
	}
	if err := tree.Close(); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(k.events, []string{"mount:" + target, "chown:" + target, "unmount:" + target, "unmount:" + tree.root}) {
		t.Fatal(k.events)
	}
}

func TestOverlayRejectsSymlinkLower(t *testing.T) {
	root := t.TempDir()
	lower := filepath.Join(root, "link")
	if err := os.Symlink(t.TempDir(), lower); err != nil {
		t.Fatal(err)
	}
	k := &fakeMountKernel{}
	tree := testTree(t, k, true)
	k.mounts = nil
	if err := tree.overlay(lower, "store", 0); err == nil || len(k.mounts) != 0 {
		t.Fatal("mounted a symlink lower")
	}
	if err := tree.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestFailedExportRetainsTheExistingTree(t *testing.T) {
	k := &fakeMountKernel{}
	tree := testTree(t, k, true)
	if err := tree.overlay(t.TempDir(), "store", 0); err != nil {
		t.Fatal(err)
	}
	target := t.TempDir()
	if err := tree.export(target); err != nil {
		t.Fatal(err)
	}
	k.failMount = t.TempDir()
	if err := tree.export(k.failMount); err == nil {
		t.Fatal("expected second export failure")
	}
	k.events = nil
	if err := tree.Close(); err != nil {
		t.Fatal(err)
	}
	want := []string{"unmount:" + filepath.Join(target, "store"), "unmount:" + target,
		"unmount:" + filepath.Join(tree.root, "store"), "unmount:" + tree.root}
	if !slices.Equal(k.events, want) {
		t.Fatal(k.events)
	}
}

func TestTreeRejectsChangesAfterExportOrClose(t *testing.T) {
	k := &fakeMountKernel{}
	tree := testTree(t, k, true)
	if err := tree.export(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	k.mounts = nil
	if err := tree.overlay(t.TempDir(), "store", 0); err == nil || len(k.mounts) != 0 {
		t.Fatal("changed the tree after cloning it")
	}
	if err := tree.Close(); err != nil {
		t.Fatal(err)
	}
	if err := tree.export(t.TempDir()); err == nil || len(k.mounts) != 0 {
		t.Fatal("exported a closed tree")
	}
	if err := tree.overlay(t.TempDir(), "store", 0); err == nil || len(k.mounts) != 0 {
		t.Fatal("added an overlay to a closed tree")
	}
}
