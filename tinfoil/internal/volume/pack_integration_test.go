//go:build integration

package volume

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"tinfoil/internal/bootstate"
	"tinfoil/internal/modelpack"
)

func TestMountEncryptedModelPackIntegration(t *testing.T) {
	if os.Getenv("TINFOIL_EMWP_INTEGRATION") != "1" {
		t.Skip("set TINFOIL_EMWP_INTEGRATION=1 to run")
	}

	ref := os.Getenv("TINFOIL_EMWP_REF")
	key := os.Getenv("TINFOIL_EMWP_KEY_B64")
	repo := os.Getenv("TINFOIL_EMWP_REPO")
	device := os.Getenv("TINFOIL_EMWP_DEVICE")
	if ref == "" || key == "" || repo == "" || device == "" {
		t.Fatal("TINFOIL_EMWP_REF, TINFOIL_EMWP_KEY_B64, TINFOIL_EMWP_REPO, and TINFOIL_EMWP_DEVICE are required")
	}

	masterKey, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(masterKey)
	mountPoint := bootstate.PrivateModelsDir + "/emwp-integration"
	if err := os.MkdirAll(mountPoint, 0700); err != nil {
		t.Fatal(err)
	}
	mounted := &mountedVolume{definition: Definition{Target: mountPoint, Filesystem: "erofs", Access: "ro"}}
	t.Cleanup(func() {
		if err := mounted.Close(); err != nil {
			t.Error(err)
		}
	})
	pack, err := modelpack.Open(modelpack.Source{Ref: ref, Repo: repo, Encrypted: true}, device, masterKey)
	if pack != nil {
		mounted.undo = append(mounted.undo, pack.Close)
	}
	if err != nil {
		t.Fatal(err)
	}
	tree, err := mountDevice(linuxMountKernel{}, pack.Path(), pack.DeviceNumber(), mounted.definition)
	if tree != nil {
		mounted.tree = tree
		mounted.undo = append(mounted.undo, tree.Close)
	}
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(mountPoint, "config.json")); err != nil {
		t.Fatalf("checking mounted file: %v", err)
	}
}
