package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"reflect"
	"strings"
	"testing"

	sharedconfig "github.com/tinfoilsh/tinfoil-config"

	shimconfig "tinfoil/internal/config"
	"tinfoil/internal/volume"
)

func TestMountVolumesUsesDeclaredLayoutAndClearsKeys(t *testing.T) {
	config := &Config{
		Models: []ModelSpec{{Name: "nix"}, {Name: "model"}},
		Volumes: []sharedconfig.VolumeSpec{
			{Name: "runtime"},
			{Name: "workspace", KeySecret: "WORKSPACE_KEY", Exec: true, Owner: 1000,
				Overlays: []sharedconfig.VolumeOverlay{{Model: "nix", Source: "nix/store", Target: "store"}}},
			{Name: "state", KeySecret: "STATE_KEY"},
		},
	}
	workspaceKey := bytes.Repeat([]byte{0x5a}, volume.KeyBytes)
	stateKey := bytes.Repeat([]byte{0xa5}, volume.KeyBytes)
	external := &shimconfig.ExternalConfig{Secrets: map[string]string{
		"WORKSPACE_KEY": " \n" + base64.StdEncoding.EncodeToString(workspaceKey) + "\n",
		"STATE_KEY":     base64.StdEncoding.EncodeToString(stateKey),
	}}
	wantLayouts := []volume.Spec{
		{VolumeSpec: config.Volumes[1], Models: 2, Index: 1},
		{VolumeSpec: config.Volumes[2], Models: 2, Index: 2},
	}
	wantKeys := [][]byte{workspaceKey, stateKey}
	var layouts []volume.Spec
	var keys [][]byte
	err := mountVolumes(t.Context(), config, external, func(_ context.Context, spec volume.Spec, key []byte) error {
		if !bytes.Equal(key, wantKeys[len(keys)]) {
			t.Fatalf("wrong key for volume %s", spec.Name)
		}
		layouts = append(layouts, spec)
		keys = append(keys, key)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(layouts, wantLayouts) {
		t.Fatalf("mounted layouts = %#v, want %#v", layouts, wantLayouts)
	}
	for _, key := range keys {
		if !bytes.Equal(key, make([]byte, volume.KeyBytes)) {
			t.Fatal("decoded key retained after mount")
		}
	}
}

func TestMountVolumesRejectsUnusableKeysBeforeMounting(t *testing.T) {
	config := &Config{Volumes: []sharedconfig.VolumeSpec{{Name: "state", KeySecret: "VOLUME_KEY"}}}
	for name, secret := range map[string]string{
		"unresolved": "",
		"malformed":  "not-base64",
		"short":      base64.StdEncoding.EncodeToString(make([]byte, volume.KeyBytes-1)),
		"long":       base64.StdEncoding.EncodeToString(make([]byte, volume.KeyBytes+1)),
	} {
		t.Run(name, func(t *testing.T) {
			external := &shimconfig.ExternalConfig{Secrets: map[string]string{"VOLUME_KEY": secret}}
			err := mountVolumes(t.Context(), config, external, func(context.Context, volume.Spec, []byte) error {
				t.Fatal("mount attempted with invalid key")
				return nil
			})
			if err == nil || !strings.Contains(err.Error(), "volume state key VOLUME_KEY") {
				t.Fatalf("error = %v, want volume and secret name", err)
			}
			if secret != "" && strings.Contains(err.Error(), secret) {
				t.Fatal("error contains secret value")
			}
		})
	}
}
