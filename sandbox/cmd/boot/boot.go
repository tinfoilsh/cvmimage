package main

import (
	"fmt"
	"path/filepath"

	runtimeconfig "github.com/tinfoilsh/tinfoil-config"

	"tinfoil/boot"
	"tinfoil/internal/attestation"
	"tinfoil/internal/volume"
	"tinfoil/sandbox/internal/variant"
)

func bootSpec() boot.Spec {
	return boot.Spec{Stages: variant.BootStages(), Configure: configureWorkload}
}

func configureWorkload(config *runtimeconfig.Config) (boot.Workload, error) {
	if err := validate(config); err != nil {
		return boot.Workload{}, err
	}
	plan, err := volume.Compile(config)
	if err != nil {
		return boot.Workload{}, err
	}
	name, toolchain, err := runtimeconfig.WorkspaceRoles(config)
	if err != nil {
		return boot.Workload{}, err
	}
	if err := workspacePlan(&plan, name, toolchain); err != nil {
		return boot.Workload{}, err
	}
	if err := plan.Validate(); err != nil {
		return boot.Workload{}, err
	}
	return boot.Workload{Volumes: plan, DeviceEvidence: attestation.NoDeviceEvidence}, nil
}

func validate(config *runtimeconfig.Config) error {
	if config.GPUs != 0 {
		return fmt.Errorf("gpus are not supported by the sandbox image")
	}
	if len(config.Containers) != 0 {
		return fmt.Errorf("containers are not supported by the sandbox image")
	}
	if len(runtimeconfig.Disks(config)) != 1 && config.Sandbox == nil {
		return fmt.Errorf("the sandbox image takes exactly one volume, got %d", len(runtimeconfig.Disks(config)))
	}
	return nil
}

// Workspace compiles the sandbox's fixed host exports into ordinary storage
// operations. The engine never accepts filesystem paths from an unlock caller.
func workspacePlan(p *volume.Plan, name, toolchain string) error {
	var disk, pack *volume.Definition
	for i := range p.Volumes {
		d := &p.Volumes[i]
		if d.Name == name {
			disk = d
		}
		if d.Name == toolchain {
			pack = d
		}
	}
	if disk == nil || disk.Disk == nil || disk.Access != "rw" || !disk.Exec || pack == nil || pack.Pack == nil || !pack.Exec {
		return fmt.Errorf("sandbox requires a writable executable workspace and executable toolchain pack")
	}
	if disk.Unlock.Runtime != "owner" {
		return fmt.Errorf("sandbox workspace requires owner unlock")
	}
	found := false
	for _, overlay := range disk.Overlays {
		if overlay.Volume == toolchain && overlay.Source == "nix/store" && overlay.Target == "store" {
			found = true
		}
	}
	if !found {
		return fmt.Errorf("sandbox workspace requires toolchain nix/store overlay at store")
	}
	disk.Exports = []string{"/workspace", "/nix"}
	disk.Directories = []volume.Directory{{Path: "home", Mode: 0700}, {Path: "var/nix/profiles", Mode: 0755}}
	disk.Links = []volume.Link{{Path: "var/nix/profiles/default", Target: filepath.Join(pack.Target, "nix/var/nix/profiles/default")}}
	return nil
}
