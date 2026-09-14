package sandboxvariant

import (
	"testing"
	"tinfoil/internal/config"
	"tinfoil/internal/runtimeconfig"
)

func TestSandboxRequiresEnrollmentWorkspaceAndLoopbackAPI(t *testing.T) {
	valid := func() *runtimeconfig.Config {
		return &runtimeconfig.Config{
			ShimCfg: &config.Config{UpstreamPort: 8080},
			Models:  []runtimeconfig.ModelSpec{{Name: "nix", Exec: true}},
			Volumes: []runtimeconfig.VolumeSpec{{Name: "workspace", Exec: true, Overlays: []runtimeconfig.VolumeOverlay{{Model: "nix", Source: "nix/store", Target: "store"}}}},
		}
	}
	if err := Validate(valid()); err != nil {
		t.Fatal(err)
	}
	for i, change := range []func(*runtimeconfig.Config){
		func(c *runtimeconfig.Config) { c.GPUs = 1 },
		func(c *runtimeconfig.Config) { c.Containers = []runtimeconfig.Container{{Name: "container"}} },
		func(c *runtimeconfig.Config) { c.Volumes = nil },
		func(c *runtimeconfig.Config) { c.Volumes[0].KeySecret = "HOST_KEY" },
		func(c *runtimeconfig.Config) { c.Volumes[0].Overlays[0].Target = "elsewhere" },
		func(c *runtimeconfig.Config) { c.Models[0].Exec = false },
		func(c *runtimeconfig.Config) { c.Models[0].Name = "another" },
		func(c *runtimeconfig.Config) { c.ShimCfg.UpstreamPort = 9000 },
		func(c *runtimeconfig.Config) { c.ShimCfg.UpstreamContainer = "container" },
	} {
		c := valid()
		change(c)
		if Validate(c) == nil {
			t.Fatalf("accepted mutation %d", i)
		}
	}
}
