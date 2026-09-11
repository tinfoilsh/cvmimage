package main

import (
	"testing"

	runtimeconfig "github.com/tinfoilsh/tinfoil-config"

	"tinfoil/internal/bootstate"
)

func TestWorkloadDeclaresPrivateAndLegacyMounts(t *testing.T) {
	const hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const ref = hash + "_4096_0eefa619-50b7-588f-a072-d405fb439d36"
	config := &runtimeconfig.Config{
		Models: []runtimeconfig.ModelSpec{
			{Name: "private", EMWP: ref, KeySecret: "MODEL_KEY", Exec: true},
			{Name: "public", MWP: ref},
		},
		Containers: []runtimeconfig.Container{{Models: []string{"private"}, Secrets: []string{"API_KEY"}}},
	}
	workload, err := bootSpec().Configure(config)
	if err != nil {
		t.Fatal(err)
	}
	private, public := workload.Mounts[0], workload.Mounts[1]
	if private.Disk != 0 || private.Target != bootstate.PrivateModelsDir+"/private" || private.LegacyAlias || private.Model.KeySecret != "MODEL_KEY" || !private.Model.Exec {
		t.Fatal("private mount declaration changed")
	}
	if public.Disk != 1 || public.Target != bootstate.MWPDir+"/mwp-"+hash || !public.LegacyAlias || public.Model.Exec {
		t.Fatal("legacy mount declaration changed")
	}
	if len(workload.Secrets) != 1 || workload.Secrets[0] != "API_KEY" {
		t.Fatal("workload secrets include model keys")
	}
}
