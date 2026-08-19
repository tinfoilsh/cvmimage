//go:build integration

package main

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"

	"tinfoil/internal/boot"
	shimconfig "tinfoil/internal/config"
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

	spec, err := parseModelPackRef(ref)
	if err != nil {
		t.Fatalf("parsing EMWP ref: %v", err)
	}
	mountPoint := boot.PrivateModelsDir + "/emwp-integration"
	cleanupEMWPIntegration(spec, mountPoint)
	t.Cleanup(func() {
		cleanupEMWPIntegration(spec, mountPoint)
	})

	err = mountEncryptedModelPack(ModelSpec{
		Name:      "emwp-integration",
		Repo:      repo,
		EMWP:      ref,
		KeySecret: "PRIVATE_MODEL_KEY",
	}, &shimconfig.ExternalConfig{
		Secrets: map[string]string{"PRIVATE_MODEL_KEY": key},
	}, device, mountPoint)
	if err != nil {
		t.Fatalf("mounting EMWP: %v", err)
	}

	if _, err := os.Stat(filepath.Join(mountPoint, "config.json")); err != nil {
		t.Fatalf("checking mounted file: %v", err)
	}
}

func cleanupEMWPIntegration(spec *modelPackRef, mountPoint string) {
	_ = unix.Unmount(mountPoint, 0)
	ops := directModelVolumeOps{}
	_ = ops.remove(spec.mapperName())
	_ = ops.remove("emwp-" + spec.RootHash + "-crypt")
}
