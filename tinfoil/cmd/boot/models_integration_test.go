//go:build integration

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/tinfoilsh/modelwrap/unwrap"

	shimconfig "tinfoil/internal/config"
)

func TestMountEncryptedModelPackIntegration(t *testing.T) {
	if os.Getenv("TINFOIL_EMWP_INTEGRATION") != "1" {
		t.Skip("set TINFOIL_EMWP_INTEGRATION=1 to run")
	}

	ref := os.Getenv("TINFOIL_EMWP_REF")
	key := os.Getenv("TINFOIL_EMWP_KEY_B64")
	device := os.Getenv("TINFOIL_EMWP_DEVICE")
	if ref == "" || key == "" || device == "" {
		t.Fatal("TINFOIL_EMWP_REF, TINFOIL_EMWP_KEY_B64, and TINFOIL_EMWP_DEVICE are required")
	}

	spec, err := parseModelPackRef(ref)
	if err != nil {
		t.Fatalf("parsing EMWP ref: %v", err)
	}
	cleanupEMWPIntegration(spec)
	t.Cleanup(func() {
		cleanupEMWPIntegration(spec)
	})

	err = mountEncryptedModelPack(ModelSpec{
		Name:      "emwp-integration",
		EMWP:      ref,
		KeySecret: "PRIVATE_MODEL_KEY",
	}, &shimconfig.ExternalConfig{
		Secrets: map[string]string{"PRIVATE_MODEL_KEY": key},
	}, device)
	if err != nil {
		t.Fatalf("mounting EMWP: %v", err)
	}

	if _, err := os.Stat(filepath.Join(spec.mountPoint(), "config.json")); err != nil {
		t.Fatalf("checking mounted file: %v", err)
	}
	if _, err := os.Lstat(spec.legacyMountPoint()); err != nil {
		t.Fatalf("checking legacy mount alias: %v", err)
	}
}

func cleanupEMWPIntegration(spec *modelPackRef) {
	_ = exec.Command("umount", spec.mountPoint()).Run()
	unwrap.CloseVerity(spec.mapperName())
	unwrap.CloseCrypt(fmt.Sprintf("emwp-%s-crypt", spec.RootHash))
	removeLegacyModelPackAlias(spec)
}
