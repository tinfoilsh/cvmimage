package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"gopkg.in/yaml.v3"
	"tinfoil/internal/attestedkeys"
	"tinfoil/internal/runtimeconfig"
)

func TestShimLoadsOnlyCompleteMeasuredKeyInventory(t *testing.T) {
	dir := t.TempDir()
	configPath, store := filepath.Join(dir, "config.yml"), filepath.Join(dir, "keys")
	cfg := &runtimeconfig.Config{CVMVersion: "0.15.0", AttestedKeys: []runtimeconfig.AttestedKey{
		{ID: "host-ssh", Key: "ecdsa-p256", UID: os.Geteuid(), GID: os.Getegid()},
	}, Containers: []runtimeconfig.Container{{Name: "ubuntu", Keys: []string{"host-ssh"}}}}
	writeConfig := func() {
		data, err := yaml.Marshal(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(configPath, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	writeConfig()
	if _, err := loadWorkloadKeys(configPath, store); err == nil {
		t.Fatal("shim accepted keys before boot generated them")
	}
	want, err := attestedkeys.Ensure(store, cfg)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		got, err := loadWorkloadKeys(configPath, store)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("shim restart changed keys: %v", err)
		}
	}
	cfg.Containers[0].Name = "different"
	writeConfig()
	if _, err := loadWorkloadKeys(configPath, store); err == nil {
		t.Fatal("shim accepted mismatched measured grant")
	}
	cfg.Containers[0].Name = "ubuntu"
	writeConfig()
	if err := os.Remove(filepath.Join(store, "inventory.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := loadWorkloadKeys(configPath, store); err == nil {
		t.Fatal("shim silently omitted a missing key")
	}
	if _, err := os.Stat(filepath.Join(store, "inventory.json")); !os.IsNotExist(err) {
		t.Fatal("shim generated a replacement key")
	}
}
