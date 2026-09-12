package containers

import (
	"slices"
	"testing"
	"tinfoil/internal/volume"
)

func TestVolumeBindingsUseExplicitGuestPathsAndMeasuredAccess(t *testing.T) {
	ready := volume.ReadyVolumes{"state": {Path: "/resolved/storage-state", Access: "rw"}, "weights": {Path: "/resolved/pack-weights", Access: "ro"}}
	c := Container{Models: []string{"weights"}, Volumes: []string{"state:/data", "weights:/weights", "state:/snapshot:ro"}}
	got, err := storageBindings(c, ready, false)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"/resolved/pack-weights:/tinfoil/models/weights:ro", "/resolved/storage-state:/data:rw", "/resolved/pack-weights:/weights:ro", "/resolved/storage-state:/snapshot:ro"}
	if !slices.Equal(got, want) {
		t.Fatalf("bindings: %v", got)
	}
	deps, err := storageDependencies(c, false)
	if err != nil || !slices.Equal(deps, []string{"state", "weights"}) {
		t.Fatalf("dependencies: %v, %v", deps, err)
	}
	for _, bind := range []string{"weights:/weights:rw", "missing:/data", "/etc:/data", "state:relative"} {
		c.Volumes = []string{bind}
		if _, err := storageBindings(c, ready, false); err == nil {
			t.Fatalf("accepted %s", bind)
		}
	}
}
