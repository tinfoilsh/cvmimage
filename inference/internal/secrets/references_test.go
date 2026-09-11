package secrets

import (
	"slices"
	"testing"

	"tinfoil/internal/runtimeconfig"
)

func TestReferencesSelectsOnlyContainerSecrets(t *testing.T) {
	config := &runtimeconfig.Config{
		Models: []runtimeconfig.ModelSpec{{KeySecret: "MODEL_KEY"}},
		Containers: []runtimeconfig.Container{
			{Secrets: []string{"SHARED", "API_KEY"}},
			{Secrets: []string{"SHARED"}},
		},
	}
	if got := References(config); !slices.Equal(got, []string{"API_KEY", "SHARED"}) {
		t.Fatalf("container secrets = %v", got)
	}
	if !slices.Equal(config.Containers[0].Secrets, []string{"SHARED", "API_KEY"}) {
		t.Fatal("selection mutated the measured config")
	}
}
