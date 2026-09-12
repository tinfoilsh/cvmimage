package volume

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"tinfoil/internal/bootstate"
	"tinfoil/internal/modelpack"
)

// publicPackTarget preserves the mount location used by ungranted legacy packs.
func publicPackTarget(source modelpack.Source) string {
	return filepath.Join(bootstate.MWPDir, source.MapperName())
}

func legacyAliasPath(source modelpack.Source) string {
	return filepath.Join(bootstate.MPKDir, "mpk-"+strings.TrimPrefix(source.MapperName(), "mwp-"))
}

func (r *mountedVolume) createLegacyAlias() error {
	d := r.definition
	if d.Pack == nil || d.Pack.Encrypted || d.Target != publicPackTarget(*d.Pack) {
		return fmt.Errorf("legacy alias requires a public plaintext pack")
	}
	return r.createAlias(legacyAliasPath(*d.Pack), "../mwp/"+d.Pack.MapperName())
}

func (r *mountedVolume) createAlias(path, target string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink == 0 {
			return fmt.Errorf("legacy pack alias is not a symlink: %s", path)
		}
		if err := os.Remove(path); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.Symlink(target, path); err != nil {
		return err
	}
	r.undo = append(r.undo, func() error { return os.Remove(path) })
	return nil
}
