//go:build storageintegration

package volume

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/tinfoilsh/modelwrap/wrap"

	"tinfoil/internal/modelpack"
)

type packFixture struct {
	Source modelpack.Source
	Image  string
}

func fixturePackKey() []byte { return bytes.Repeat([]byte{0x47}, 64) }

// Build fixtures on the host with the real packer. Only the resulting images
// and references are passed into the disposable VM.
func makePackFixtures(directory string) error {
	keyFile := filepath.Join(directory, "pack-key")
	if err := os.WriteFile(keyFile, []byte(base64.StdEncoding.EncodeToString(fixturePackKey())), 0600); err != nil {
		return err
	}
	var fixtures []packFixture
	for _, name := range []string{"lower", "encrypted"} {
		input := filepath.Join(directory, name)
		if err := os.MkdirAll(filepath.Join(input, "store"), 0700); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(input, "store/tool"), []byte("toolchain\n"), 0600); err != nil {
			return err
		}
		// Keep data outside the metadata block so the fixture has a verity tree.
		if err := os.WriteFile(filepath.Join(input, "store/payload"), bytes.Repeat([]byte{0xa7}, 8192), 0600); err != nil {
			return err
		}
		encrypted := name == "encrypted"
		repo := "test/" + name + "@fixture"
		output := filepath.Join(directory, "packs")
		ref, err := wrap.Pack(wrap.Options{
			Model: repo, ModelDir: input, OutputDir: output,
			CacheDir: filepath.Join(directory, "cache"), Encrypt: encrypted, KeyFile: keyFile,
		})
		if err != nil {
			return err
		}
		extension := ".mpk"
		if encrypted {
			extension = ".emwp"
		}
		fixtures = append(fixtures, packFixture{
			Source: modelpack.Source{Ref: ref, Repo: repo, Encrypted: encrypted},
			Image:  filepath.Join(output, "test", name, "fixture"+extension),
		})
	}
	data, err := json.Marshal(fixtures)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(directory, "initramfs/packs.json"), data, 0600)
}
