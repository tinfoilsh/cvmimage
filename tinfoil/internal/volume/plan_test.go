package volume

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"

	config "github.com/tinfoilsh/tinfoil-config"

	"tinfoil/internal/bootstate"
	"tinfoil/internal/secretstore"
)

func packRef(hash string) string {
	return strings.Repeat(hash, 64) + "_4096_0eefa619-50b7-588f-a072-d405fb439d36"
}

func mixedConfig() *config.Config {
	return &config.Config{
		Models: []config.ModelSpec{{Name: "Legacy.Model", Repo: "org/legacy@rev", MWP: packRef("a")}, {Name: "encrypted", Repo: "org/encrypted@rev", EMWP: packRef("b"), KeySecret: "PACK_KEY"}},
		Volumes: []config.VolumeSpec{
			{Name: "state", Source: config.VolumeSource{Disk: "state"}, Unlock: config.VolumeUnlock{Secret: "DISK_KEY"}, Overlays: []config.VolumeOverlay{{Model: "tools", Source: "nix/store", Target: "store"}}},
			{Name: "tools", Source: config.VolumeSource{Pack: &config.ModelSpec{Repo: "org/tools@rev", MWP: packRef("c")}}},
		},
	}
}

func TestCompilePreservesSlotOrderAndDoesNotMutateConfig(t *testing.T) {
	c := mixedConfig()
	before, _ := json.Marshal(c)
	p, err := Compile(c, "Legacy.Model")
	if err != nil {
		t.Fatal(err)
	}
	after, _ := json.Marshal(c)
	if string(before) != string(after) {
		t.Fatal("compilation mutated input config")
	}
	// Layout may still relocate a private pack before validation.
	p.Volumes[2].Target = "/resolved/toolchain"
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	wantNames := []string{"Legacy.Model", "encrypted", "tools", "state"}
	wantSerials := []string{"tinfoil-modelwrap1", "tinfoil-modelwrap2", "tinfoil-modelwrap3", "tinfoil-volume1"}
	for i, d := range p.Volumes {
		if d.Name != wantNames[i] || d.Device.Serial != wantSerials[i] {
			t.Fatalf("slot %d: %+v", i, d)
		}
	}
	if p.Volumes[1].Device.Partition != 1 || p.Volumes[0].Device.Partition != 0 || p.Volumes[3].Device.PCIAddress != "0000:00:0a.0" {
		t.Fatal("device identities changed")
	}
	if p.Volumes[1].Target != bootstate.PrivateModelsDir+"/encrypted" || p.Volumes[1].Unlock.Secret != "PACK_KEY" {
		t.Fatal("legacy key or private placement lost")
	}
	disk := p.Volumes[3]
	if disk.Disk.Initialize != "never" || disk.Filesystem != "ext4" || disk.Access != "rw" {
		t.Fatal("disk defaults lost")
	}
	if !slices.Equal(p.SecretReferences(), []string{"DISK_KEY", "PACK_KEY"}) {
		t.Fatal(p.SecretReferences())
	}
	p.Digest = "measured-config"
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Plan
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if err := decoded.Validate(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(p, decoded) {
		t.Fatal("plan did not roundtrip")
	}
}

func TestCompileLegacyPlacementUsesNames(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		c := mixedConfig()
		c.Models = append(c.Models,
			config.ModelSpec{Name: "private", Repo: "org/private@rev", MWP: packRef("d")},
			config.ModelSpec{Repo: "org/unnamed@rev", MPK: packRef("e")},
		)
		if reverse {
			slices.Reverse(c.Models)
		}
		p, err := Compile(c, "Legacy.Model", "encrypted", "", "tools")
		if err != nil {
			t.Fatal(err)
		}
		if err := p.Validate(); err != nil {
			t.Fatal(err)
		}
		for _, d := range p.Volumes {
			if d.Pack == nil {
				continue
			}
			public := d.Name == "Legacy.Model" || d.Name == "encrypted" || strings.HasPrefix(d.Name, "legacy-model-")
			want := bootstate.PrivateModelsDir + "/" + d.Name
			if public {
				want = bootstate.MWPDir + "/mwp-" + strings.Split(d.Pack.Ref, "_")[0]
			}
			if d.Target != want || d.LegacyAlias != (public && !d.Pack.Encrypted) {
				t.Fatalf("reverse=%t, volume %s: target=%s alias=%t", reverse, d.Name, d.Target, d.LegacyAlias)
			}
		}
	}
}

func TestCompileRejectsUnsupportedDiskFormat(t *testing.T) {
	c := mixedConfig()
	c.Volumes[0].Format = "unknown"
	if _, err := Compile(c); err == nil || !strings.Contains(err.Error(), "unsupported disk format") {
		t.Fatalf("unsupported disk format: %v", err)
	}
}

func TestCompiledPlanRejectsInconsistentResources(t *testing.T) {
	for _, tt := range []struct {
		name   string
		change func(*Plan)
	}{
		{"duplicate name", func(p *Plan) { p.Volumes[1].Name = p.Volumes[0].Name }},
		{"duplicate mapping", func(p *Plan) { p.Volumes[1].Pack.Ref = p.Volumes[0].Pack.Ref }},
		{"duplicate target", func(p *Plan) { p.Volumes[1].Target = p.Volumes[0].Target }},
		{"wrong serial", func(p *Plan) { p.Volumes[3].Device.Serial = "tinfoil-volume2" }},
		{"wrong partition", func(p *Plan) { p.Volumes[1].Device.Partition = 0 }},
		{"writable pack", func(p *Plan) { p.Volumes[0].Access = "rw" }},
		{"two sources", func(p *Plan) { p.Volumes[0].Disk = &DiskSource{} }},
		{"missing source", func(p *Plan) { p.Volumes[0].Pack = nil }},
		{"unknown lower", func(p *Plan) { p.Volumes[3].Overlays[0].Volume = "absent" }},
		{"relative escape", func(p *Plan) { p.Volumes[3].Overlays[0].Source = "../escape" }},
		{"readonly initialization", func(p *Plan) { p.Volumes[3].Access = "ro"; p.Volumes[3].Disk.Initialize = "if-empty" }},
		{"owner pack", func(p *Plan) { p.Volumes[1].Unlock = config.VolumeUnlock{Runtime: "owner"} }},
		{"exec overlay on noexec pack", func(p *Plan) { p.Volumes[3].Exec = true }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p, err := Compile(mixedConfig())
			if err != nil {
				t.Fatal(err)
			}
			tt.change(&p)
			if err := p.Validate(); err == nil {
				t.Fatal("accepted inconsistent plan")
			}
		})
	}
}

func TestPlanHandoffResolvesOverlayMountsAtActivation(t *testing.T) {
	p, err := Compile(mixedConfig())
	if err != nil {
		t.Fatal(err)
	}
	p.Volumes[2].Target = "/relocated/toolchain"
	p.Volumes[3].Overlays = append(p.Volumes[3].Overlays, Overlay{Volume: "tools", Source: "nix/cache", Target: "cache"})
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Plan
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if err := decoded.Validate(); err != nil {
		t.Fatal(err)
	}
	key := base64.StdEncoding.EncodeToString(make([]byte, 64))
	var lowers map[string]string
	b := &fakeBackend{}
	b.prepare = func(_ context.Context, d Definition, _ []byte, paths map[string]string) (resource, error) {
		if d.Name == "state" {
			lowers = paths
		}
		return &fakeResource{backend: b, name: d.Name}, nil
	}
	m := testManager(t, decoded, secretstore.Store{"PACK_KEY": key, "DISK_KEY": key}, b)
	t.Cleanup(func() {
		if err := m.Close(); err != nil {
			t.Error(err)
		}
	})
	if err := m.OpenInitial(t.Context(), []string{"state"}); err != nil {
		t.Fatal(err)
	}
	if len(lowers) != 1 || lowers["tools"] != "/relocated/toolchain" {
		t.Fatalf("ready lower mounts: %v", lowers)
	}
	if m.Snapshot().Volumes[3].Phase != "ready" {
		t.Fatal("upper volume did not activate")
	}
}
