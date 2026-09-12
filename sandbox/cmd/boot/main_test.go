package main

import (
	"slices"
	"strings"
	"testing"

	runtimeconfig "github.com/tinfoilsh/tinfoil-config"

	"tinfoil/internal/bootstate"
)

func TestSandboxBootPolicy(t *testing.T) {
	spec := bootSpec()
	valid := runtimeconfig.Config{Volumes: []runtimeconfig.VolumeSpec{{Name: "workspace", Exec: true, Filesystem: "ext4", Access: "rw", Unlock: runtimeconfig.VolumeUnlock{Runtime: "owner"}, Overlays: []runtimeconfig.VolumeOverlay{{Model: "toolchain", Source: "nix/store", Target: "store"}}}}, Models: []runtimeconfig.ModelSpec{{Name: "toolchain", Repo: "org/toolchain@rev", MWP: strings.Repeat("a", 64) + "_4096_0eefa619-50b7-588f-a072-d405fb439d36", Exec: true}}}
	workload, err := spec.Configure(&valid)
	if err != nil {
		t.Fatal(err)
	}
	if len(workload.Volumes.Volumes) != 2 || workload.Volumes.Volumes[0].Target != bootstate.PrivateModelsDir+"/toolchain" || workload.Volumes.Volumes[0].LegacyAlias || !workload.Volumes.Volumes[0].Exec {
		t.Fatal("toolchain pack must mount privately without a container grant")
	}
	workspace := workload.Volumes.Volumes[1]
	if workspace.Unlock.Runtime != "owner" || !slices.Equal(workspace.Exports, []string{"/workspace", "/nix"}) {
		t.Fatal("workspace publication changed")
	}
	if workspace.Overlays[0].Volume != "toolchain" || workspace.Overlays[0].Source != "nix/store" || workspace.Overlays[0].Target != "store" || workspace.Directories[0].Path != "home" || workspace.Directories[0].Mode != 0700 || workspace.Links[0].Target != bootstate.PrivateModelsDir+"/toolchain/nix/var/nix/profiles/default" {
		t.Fatal("workspace layout changed")
	}
	for _, invalid := range []runtimeconfig.Config{
		{},
		{GPUs: 1, Volumes: valid.Volumes},
		{Containers: []runtimeconfig.Container{{Name: "workload"}}, Volumes: valid.Volumes},
		{Volumes: []runtimeconfig.VolumeSpec{{}, {}}},
	} {
		if _, err := spec.Configure(&invalid); err == nil {
			t.Fatalf("accepted incompatible config: %#v", invalid)
		}
	}
}
