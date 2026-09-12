package volume

import (
	"os"
	"path/filepath"
	"testing"
)

func TestVolumeDirectoriesDoNotFollowExistingSymlinks(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := ensureDirectory(root, "home/data", 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "alias")); err != nil {
		t.Fatal(err)
	}
	if err := ensureDirectory(root, "alias/data", 0700); err == nil {
		t.Fatal("followed symlink")
	}
	if _, err := os.Stat(filepath.Join(outside, "data")); !os.IsNotExist(err) {
		t.Fatal("created directory outside volume")
	}
	for _, path := range []string{"../escape", "/absolute", "home/../escape"} {
		if err := ensureDirectory(root, path, 0700); err == nil {
			t.Fatal(path)
		}
	}
}
