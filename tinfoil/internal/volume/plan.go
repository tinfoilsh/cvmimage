// Package volume owns workload storage for every image variant.
package volume

import (
	"fmt"
	"path/filepath"
	"slices"

	config "github.com/tinfoilsh/tinfoil-config"

	"tinfoil/internal/bootstate"
	"tinfoil/internal/device"
	"tinfoil/internal/modelpack"
)

const (
	Root           = bootstate.PrivateDir + "/volumes"
	PlanPath       = bootstate.PrivateDir + "/volume-plan.json"
	Socket         = "/run/tinfoil/volumes.sock"
	Binary         = "/usr/bin/tinfoil-volumes"
	ManagementPath = "/.well-known/tinfoil-volumes"
)

type Plan struct {
	Digest  string
	Volumes []Definition
}
type Definition struct {
	Name        string
	Target      string
	Filesystem  string
	Access      string
	Exec        bool
	Unlock      config.VolumeUnlock
	Device      device.Selector
	Pack        *modelpack.Source
	Disk        *DiskSource
	LegacyAlias bool
	Overlays    []Overlay
	Exports     []string
	Directories []Directory
	Links       []Link
}
type DiskSource struct {
	Initialize string
	Owner      int
}
type Overlay struct {
	Volume string
	Source string
	Target string
}
type Directory struct {
	Path string
	Mode uint32
}
type Link struct{ Path, Target string }

// Compile resolves schema defaults and slot identities. publicLegacyPacks names
// legacy models that the variant leaves at their public, hash-based paths.
// Other packs are private. Variants add layout before validating the plan.
func Compile(c *config.Config, publicLegacyPacks ...string) (Plan, error) {
	normalized := *c
	normalized.Models = slices.Clone(c.Models)
	normalized.Volumes = slices.Clone(c.Volumes)
	for i := range normalized.Volumes {
		normalized.Volumes[i].Overlays = slices.Clone(c.Volumes[i].Overlays)
	}
	config.NormalizeStorage(&normalized)
	packs, disks := config.Packs(&normalized), config.Disks(&normalized)
	if err := device.StorageSlots(len(packs), len(disks)); err != nil {
		return Plan{}, err
	}
	p := Plan{}
	for i, model := range packs {
		source, err := modelpack.Compile(model)
		if err != nil {
			return Plan{}, err
		}
		slot, err := device.PackSelector(i, source.Encrypted)
		if err != nil {
			return Plan{}, err
		}
		name := model.Name
		if name == "" {
			name = fmt.Sprintf("legacy-model-%d", i)
		}
		d := Definition{
			Name:       name,
			Target:     filepath.Join(bootstate.PrivateModelsDir, name),
			Filesystem: model.Filesystem,
			Access:     "ro",
			Exec:       model.Exec,
			Unlock:     model.Unlock,
			Device:     slot,
			Pack:       &source,
		}
		if i < len(normalized.Models) && slices.Contains(publicLegacyPacks, model.Name) {
			d.Target = publicPackTarget(source)
			d.LegacyAlias = !source.Encrypted
		}
		p.Volumes = append(p.Volumes, d)
	}
	for i, v := range disks {
		if v.Format != "authenticated-v1" {
			return Plan{}, fmt.Errorf("volume %s: unsupported disk format %q", v.Name, v.Format)
		}
		slot, err := device.DiskSelector(len(packs), i)
		if err != nil {
			return Plan{}, err
		}
		d := Definition{
			Name:       v.Name,
			Target:     filepath.Join(Root, v.Name),
			Filesystem: v.Filesystem,
			Access:     v.Access,
			Exec:       v.Exec,
			Unlock:     v.Unlock,
			Device:     slot,
			Disk:       &DiskSource{Initialize: v.Initialize, Owner: v.Owner},
		}
		for _, o := range v.Overlays {
			d.Overlays = append(d.Overlays, Overlay{Volume: o.Model, Source: o.Source, Target: o.Target})
		}
		p.Volumes = append(p.Volumes, d)
	}
	return p, nil
}

func (p Plan) SecretReferences() []string {
	var names []string
	for _, d := range p.Volumes {
		if d.Unlock.Secret != "" {
			names = append(names, d.Unlock.Secret)
		}
	}
	slices.Sort(names)
	return slices.Compact(names)
}
