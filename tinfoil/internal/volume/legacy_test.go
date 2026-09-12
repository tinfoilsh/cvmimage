package volume

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"tinfoil/internal/bootstate"
	"tinfoil/internal/modelpack"
)

func TestLegacyAliasLayoutAndCleanup(t *testing.T) {
	source := modelpack.Source{Ref: packRef("a"), Repo: "org/model@rev"}
	if got := publicPackTarget(source); got != bootstate.MWPDir+"/mwp-"+strings.Repeat("a", 64) {
		t.Fatal(got)
	}
	if got := legacyAliasPath(source); got != bootstate.MPKDir+"/mpk-"+strings.Repeat("a", 64) {
		t.Fatal(got)
	}
	for _, existing := range []string{"absent", "symlink", "file"} {
		t.Run(existing, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "alias")
			switch existing {
			case "symlink":
				if err := os.Symlink("stale", path); err != nil {
					t.Fatal(err)
				}
			case "file":
				if err := os.WriteFile(path, nil, 0600); err != nil {
					t.Fatal(err)
				}
			}
			var aliasAtUnmount bool
			r := &mountedVolume{undo: []func() error{func() error {
				_, err := os.Lstat(path)
				aliasAtUnmount = err == nil
				return nil
			}}}
			if err := r.createAlias(path, "../mwp/"+source.MapperName()); (err != nil) != (existing == "file") {
				t.Fatal(err)
			}
			if existing != "file" {
				if got, err := os.Readlink(path); err != nil || got != "../mwp/"+source.MapperName() {
					t.Fatal(got, err)
				}
			}
			if err := r.Close(); err != nil {
				t.Fatal(err)
			}
			if aliasAtUnmount != (existing == "file") {
				t.Fatal("alias cleanup did not respect ownership")
			}
		})
	}
	for _, d := range []Definition{
		{Target: publicPackTarget(source)},
		{Target: "/private/model", Pack: &source},
		{Target: publicPackTarget(source), Pack: &modelpack.Source{Ref: source.Ref, Repo: source.Repo, Encrypted: true}},
	} {
		r := &mountedVolume{definition: d}
		if err := r.createLegacyAlias(); err == nil {
			t.Fatal("accepted invalid legacy alias placement")
		}
	}
}
