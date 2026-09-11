package main

import (
	"testing"

	runtimeconfig "github.com/tinfoilsh/tinfoil-config"

	"tinfoil/internal/bootstate"
)

func TestSandboxBootPolicy(t *testing.T) {
	spec := bootSpec()
	valid := runtimeconfig.Config{Volumes: []runtimeconfig.VolumeSpec{{}}, Models: []runtimeconfig.ModelSpec{{Name: "toolchain", Exec: true}}}
	workload, err := spec.Configure(&valid)
	if err != nil {
		t.Fatal(err)
	}
	if len(workload.Mounts) != 1 || workload.Mounts[0].Target != bootstate.PrivateModelsDir+"/toolchain" || workload.Mounts[0].LegacyAlias || !workload.Mounts[0].Model.Exec {
		t.Fatal("toolchain pack must mount privately without a container grant")
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
