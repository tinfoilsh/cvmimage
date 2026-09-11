package main

import (
	"testing"

	"tinfoil/boot"
	"tinfoil/internal/runtimeconfig"
)

func TestSandboxBootPolicy(t *testing.T) {
	spec := bootSpec()
	valid := boot.Config{Volumes: []runtimeconfig.VolumeSpec{{}}}
	if err := spec.Validate(&valid); err != nil {
		t.Fatal(err)
	}
	if !spec.IsolateModel(&valid, "toolchain") {
		t.Fatal("toolchain pack must mount privately without a container grant")
	}
	for _, invalid := range []boot.Config{
		{},
		{GPUs: 1, Volumes: valid.Volumes},
		{Containers: []runtimeconfig.Container{{Name: "workload"}}, Volumes: valid.Volumes},
		{Volumes: []runtimeconfig.VolumeSpec{{}, {}}},
	} {
		if err := spec.Validate(&invalid); err == nil {
			t.Fatalf("accepted incompatible config: %#v", invalid)
		}
	}
}
