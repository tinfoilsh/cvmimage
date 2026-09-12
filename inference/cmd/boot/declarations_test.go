package main

import (
	"strings"
	"testing"

	runtimeconfig "github.com/tinfoilsh/tinfoil-config"

	"tinfoil/internal/bootstate"
)

func TestWorkloadDeclaresPrivateAndLegacyMounts(t *testing.T) {
	const hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const ref = hash + "_4096_0eefa619-50b7-588f-a072-d405fb439d36"
	config := &runtimeconfig.Config{
		Models: []runtimeconfig.ModelSpec{
			{Name: "private", Repo: "org/private@rev", EMWP: strings.Repeat("b", 64) + ref[64:], KeySecret: "MODEL_KEY", Exec: true},
			{Name: "Legacy public model", Repo: "org/public@rev", MWP: ref},
		},
		Containers: []runtimeconfig.Container{{Models: []string{"private"}, Secrets: []string{"API_KEY"}}},
	}
	workload, err := bootSpec().Configure(config)
	if err != nil {
		t.Fatal(err)
	}
	private, public := workload.Volumes.Volumes[0], workload.Volumes.Volumes[1]
	if private.Device.Serial != "tinfoil-modelwrap1" || private.Target != bootstate.PrivateModelsDir+"/private" || private.LegacyAlias || private.Unlock.Secret != "MODEL_KEY" || !private.Exec {
		t.Fatal("private mount declaration changed")
	}
	if public.Device.Serial != "tinfoil-modelwrap2" || public.Target != bootstate.MWPDir+"/mwp-"+hash || !public.LegacyAlias || public.Exec {
		t.Fatal("legacy mount declaration changed")
	}
	if len(workload.Secrets) != 1 || workload.Secrets[0] != "API_KEY" {
		t.Fatal("workload secrets include model keys")
	}
}

func TestLegacyEncryptedPackWithoutContainersHasNoAlias(t *testing.T) {
	model := runtimeconfig.ModelSpec{
		Name: "encrypted", Repo: "org/model@rev", KeySecret: "PACK_KEY",
		EMWP: strings.Repeat("a", 64) + "_4096_0eefa619-50b7-588f-a072-d405fb439d36",
	}
	workload, err := configureWorkload(&runtimeconfig.Config{Models: []runtimeconfig.ModelSpec{model}})
	if err != nil {
		t.Fatal(err)
	}
	d := workload.Volumes.Volumes[0]
	if d.Target != bootstate.MWPDir+"/mwp-"+strings.Repeat("a", 64) || d.LegacyAlias || !d.Pack.Encrypted {
		t.Fatal("legacy encrypted placement or alias behavior changed")
	}
}
