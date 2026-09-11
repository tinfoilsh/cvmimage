package main

import (
	"errors"
	"reflect"
	"testing"

	runtimeconfig "github.com/tinfoilsh/tinfoil-config"
)

func TestOverlayFailureUnmountsCompletedMountsInReverse(t *testing.T) {
	mountErr, unmountErr := errors.New("mount failed"), errors.New("unmount failed")
	overlays := []runtimeconfig.VolumeOverlay{{Target: "first"}, {Target: "second"}, {Target: "third"}}
	var unmounted []string
	err := mountOverlays(overlays, func(overlay runtimeconfig.VolumeOverlay) (string, error) {
		if overlay.Target == "third" {
			return "", mountErr
		}
		return overlay.Target, nil
	}, func(path string) error {
		unmounted = append(unmounted, path)
		if path == "second" {
			return unmountErr
		}
		return nil
	})
	if !errors.Is(err, mountErr) || !errors.Is(err, unmountErr) {
		t.Fatalf("error = %v", err)
	}
	if !reflect.DeepEqual(unmounted, []string{"second", "first"}) {
		t.Fatalf("unmounted = %v", unmounted)
	}
}

func TestSuccessfulOverlaysStayMounted(t *testing.T) {
	err := mountOverlays([]runtimeconfig.VolumeOverlay{{Target: "toolchain"}}, func(overlay runtimeconfig.VolumeOverlay) (string, error) {
		return overlay.Target, nil
	}, func(string) error {
		t.Fatal("unmounted a successful overlay")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
