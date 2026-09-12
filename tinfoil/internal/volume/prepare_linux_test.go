package volume

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestCloseRetainsDeviceUntilFilesystemCloses(t *testing.T) {
	k := &fakeMountKernel{}
	tree := testTree(t, k, false)
	k.busy = tree.root
	k.events = nil
	r := &mountedVolume{tree: tree, undo: []func() error{
		func() error { k.events = append(k.events, "close:device"); return nil }, tree.Close,
	}}
	if err := r.Close(); err == nil || !slices.Equal(k.events, []string{"unmount:" + tree.root}) {
		t.Fatalf("busy mount released backing device: %v, %v", k.events, err)
	}
	k.busy = ""
	k.events = nil
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	want := []string{"unmount:" + tree.root, "close:device"}
	if !slices.Equal(k.events, want) {
		t.Fatal(k.events)
	}
	if err := r.Close(); err != nil || !slices.Equal(k.events, want) {
		t.Fatal("repeated completed cleanup")
	}
}

func TestOverlayUsesReadyLowerPath(t *testing.T) {
	root := t.TempDir()
	lower := filepath.Join(root, "nix")
	if err := os.Mkdir(lower, 0755); err != nil {
		t.Fatal(err)
	}
	k := &fakeMountKernel{}
	tree := testTree(t, k, false)
	d := Definition{Target: tree.root, Disk: &DiskSource{}, Overlays: []Overlay{{Volume: "tools", Source: "nix", Target: "store"}}}
	r := &mountedVolume{definition: d, tree: tree, undo: []func() error{tree.Close}}
	k.mounts = nil
	if err := r.mountOverlays(nil); err == nil {
		t.Fatal("accepted missing lower")
	}
	if len(k.mounts) != 0 {
		t.Fatal("mounted without a lower")
	}
	if err := r.mountOverlays(map[string]string{"tools": root}); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(tree.root, "store")
	want := "lowerdir=" + lower + ",upperdir=" + target + ".upper,workdir=" + target + ".work"
	if len(k.mounts) != 1 || k.mounts[0].data != want {
		t.Fatalf("overlay mount = %+v", k.mounts)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
}
