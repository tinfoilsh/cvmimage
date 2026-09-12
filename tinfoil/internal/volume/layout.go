package volume

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ensureDirectory creates directories below root without following symlinks.
func ensureDirectory(root, relative string, mode os.FileMode) error {
	if relative == "." {
		return nil
	}
	if filepath.IsAbs(relative) || filepath.Clean(relative) != relative || strings.HasPrefix(relative, "..") {
		return errors.New("invalid relative directory")
	}
	current := root
	for _, component := range strings.Split(relative, "/") {
		current = filepath.Join(current, component)
		if err := os.Mkdir(current, mode); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("volume path %s is not a real directory", current)
		}
	}
	return nil
}

// ensureLink accepts an existing link only when it has the expected target.
func ensureLink(root, relative, target string) error {
	if err := ensureDirectory(root, filepath.Dir(relative), 0755); err != nil {
		return err
	}
	path := filepath.Join(root, relative)
	if err := os.Symlink(target, path); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return err
		}
		existing, err := os.Readlink(path)
		if err != nil || existing != target {
			return fmt.Errorf("unexpected existing profile link %s", path)
		}
	}
	return nil
}
