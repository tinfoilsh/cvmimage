package volume

import (
	"context"
	"crypto/sha512"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"

	"tinfoil/internal/modelpack"
)

type backingDevice interface {
	Path() string
	DeviceNumber() uint64
	Close() error
}
type mountedVolume struct {
	definition    Definition
	tree          *mountTree
	seal          func([]byte) error
	undo          []func() error
	sealAttempted bool
	published     bool
}

func (r *mountedVolume) Committed() bool { return r.sealAttempted || r.published }
func (r *mountedVolume) Close() error {
	for len(r.undo) > 0 {
		last := len(r.undo) - 1
		if err := r.undo[last](); err != nil {
			return err
		}
		r.undo = r.undo[:last]
	}
	return nil
}
func (r *mountedVolume) Publish(binding []byte) error {
	if r.Committed() {
		return errors.New("volume publication already attempted")
	}
	if r.definition.Unlock.Runtime == "owner" {
		if len(binding) == 0 {
			return errors.New("owner binding is required")
		}
		// A failed write may already have changed the hardware register.
		r.sealAttempted = true
		digest := sha512.Sum384(binding)
		if err := r.seal(digest[:]); err != nil {
			return err
		}
	}
	for _, target := range r.definition.Exports {
		if !absolutePath(target) {
			return fmt.Errorf("invalid host export %q", target)
		}
		if err := r.tree.export(target); err != nil {
			return err
		}
	}
	r.published = true
	return nil
}

func prepareVolume(ctx context.Context, d Definition, key []byte, lowerPaths map[string]string) (resource, error) {
	if !absolutePath(d.Target) {
		return nil, errors.New("invalid volume target")
	}
	if err := prepareTarget(d.Target); err != nil {
		return nil, err
	}
	r := &mountedVolume{definition: d, seal: extendSeal}
	device, initialize, err := openSource(d, key)
	if device != nil {
		r.undo = append(r.undo, device.Close)
	}
	if err != nil {
		return r, fmt.Errorf("open volume %s: %w", d.Name, err)
	}
	if initialize {
		command := exec.CommandContext(ctx, Binary, "--format", device.Path(), strconv.Itoa(d.Disk.Owner))
		command.Env = []string{}
		command.Stdout = io.Discard
		command.Stderr = io.Discard
		if err := command.Run(); err != nil {
			return r, fmt.Errorf("format volume %s: %w", d.Name, err)
		}
	}
	tree, err := mountDevice(linuxMountKernel{}, device.Path(), device.DeviceNumber(), d)
	if tree != nil {
		r.tree = tree
		r.undo = append(r.undo, tree.Close)
	}
	if err != nil {
		return r, fmt.Errorf("mount volume %s: %w", d.Name, err)
	}
	if d.LegacyAlias {
		if err := r.createLegacyAlias(); err != nil {
			return r, err
		}
	}
	if err := r.mountOverlays(lowerPaths); err != nil {
		return r, fmt.Errorf("prepare volume %s overlays: %w", d.Name, err)
	}
	if err := prepareLayout(d); err != nil {
		return r, err
	}
	return r, nil
}

func (r *mountedVolume) mountOverlays(lowerPaths map[string]string) error {
	d := r.definition
	for _, overlay := range d.Overlays {
		root, ok := lowerPaths[overlay.Volume]
		if !ok || !absolutePath(root) {
			return fmt.Errorf("overlay lower %q is unavailable", overlay.Volume)
		}
		lower := filepath.Join(root, overlay.Source)
		if err := r.tree.overlay(lower, overlay.Target, d.Disk.Owner); err != nil {
			return err
		}
	}
	return nil
}

func prepareLayout(d Definition) error {
	for _, directory := range d.Directories {
		if err := ensureDirectory(d.Target, directory.Path, os.FileMode(directory.Mode)); err != nil {
			return err
		}
	}
	for _, link := range d.Links {
		if err := ensureLink(d.Target, link.Path, link.Target); err != nil {
			return err
		}
	}
	return nil
}

func openSource(d Definition, key []byte) (backingDevice, bool, error) {
	source, err := d.Device.Resolve()
	if err != nil {
		return nil, false, err
	}
	if d.Pack != nil {
		pack, err := modelpack.Open(*d.Pack, source, key)
		if pack == nil {
			return nil, false, err
		}
		return pack, false, err
	}
	if d.Disk != nil {
		disk, initialize, err := openDisk(source, d.Name, d.Access, *d.Disk, key)
		if disk == nil {
			return nil, false, err
		}
		return disk, initialize, err
	}
	return nil, false, errors.New("volume has no source")
}
