package volume

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"tinfoil/internal/device"
)

var secretNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
var packNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

func absolutePath(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && path != "/" && !strings.ContainsAny(path, "\x00\n\r,:")
}
func relativePath(path string) bool {
	return path != "" && !filepath.IsAbs(path) && filepath.Clean(path) == path && path != ".." && !strings.HasPrefix(path, "../") && !strings.ContainsAny(path, "\x00\n\r,:")
}

// Validate checks the compiled representation at both ends of the boot handoff.
func (p Plan) Validate() error {
	byName := make(map[string]Definition, len(p.Volumes))
	targets, mappings := map[string]bool{}, map[string]bool{}
	packs, disks := 0, 0
	for _, d := range p.Volumes {
		// Ungranted legacy names are labels; their public paths use the pack hash.
		if d.Name == "" || !d.LegacyAlias && !packNamePattern.MatchString(d.Name) || d.Disk != nil && !namePattern.MatchString(d.Name) {
			return fmt.Errorf("invalid volume name %q", d.Name)
		}
		if _, exists := byName[d.Name]; exists {
			return fmt.Errorf("duplicate volume %q", d.Name)
		}
		byName[d.Name] = d
		if !absolutePath(d.Target) || targets[d.Target] {
			return fmt.Errorf("invalid or duplicate volume target %q", d.Target)
		}
		targets[d.Target] = true
		if (d.Pack == nil) == (d.Disk == nil) {
			return fmt.Errorf("volume %s requires exactly one source", d.Name)
		}
		if d.Filesystem != "erofs" && d.Filesystem != "ext4" {
			return fmt.Errorf("volume %s: unsupported filesystem", d.Name)
		}
		if d.Access != "ro" && d.Access != "rw" || d.Filesystem == "erofs" && d.Access != "ro" {
			return fmt.Errorf("volume %s: invalid access", d.Name)
		}
		u := d.Unlock
		if u.Secret != "" && (u.Runtime != "" || !secretNamePattern.MatchString(u.Secret)) || u.Runtime != "" && u.Runtime != "owner" && u.Runtime != "operator" {
			return fmt.Errorf("volume %s: invalid unlock source", d.Name)
		}
		var expected device.Selector
		var err error
		if d.Pack != nil {
			if disks != 0 {
				return fmt.Errorf("pack slots must precede disk slots")
			}
			if err := d.Pack.Validate(); err != nil {
				return fmt.Errorf("volume %s: %w", d.Name, err)
			}
			if d.Access != "ro" || len(d.Overlays) != 0 || d.Pack.Encrypted != (u.Secret != "" || u.Runtime != "") || d.LegacyAlias && d.Pack.Encrypted {
				return fmt.Errorf("volume %s: invalid pack policy", d.Name)
			}
			if d.LegacyAlias && d.Target != publicPackTarget(*d.Pack) {
				return fmt.Errorf("volume %s: legacy alias requires the public target", d.Name)
			}
			if mappings[d.Pack.MapperName()] {
				return fmt.Errorf("duplicate pack mapping %q", d.Pack.MapperName())
			}
			mappings[d.Pack.MapperName()] = true
			expected, err = device.PackSelector(packs, d.Pack.Encrypted)
			packs++
		} else {
			if d.LegacyAlias || u.Secret == "" && u.Runtime == "" || d.Disk.Owner < 0 || d.Disk.Owner > maxOwner {
				return fmt.Errorf("volume %s: invalid disk policy", d.Name)
			}
			if d.Disk.Initialize != "never" && d.Disk.Initialize != "if-empty" || d.Disk.Initialize == "if-empty" && (d.Access != "rw" || d.Filesystem != "ext4") {
				return fmt.Errorf("volume %s: invalid initialization policy", d.Name)
			}
			expected, err = device.DiskSelector(packs, disks)
			disks++
		}
		if err != nil {
			return err
		}
		if d.Device != expected {
			return fmt.Errorf("volume %s: device selector does not match measured slot", d.Name)
		}
		if u.Runtime == "owner" && d.Disk == nil {
			return fmt.Errorf("volume %s: invalid owner sealing policy", d.Name)
		}
		for _, target := range d.Exports {
			if !absolutePath(target) || targets[target] {
				return fmt.Errorf("invalid or duplicate export %q", target)
			}
			targets[target] = true
		}
		for _, dir := range d.Directories {
			if !relativePath(dir.Path) || dir.Mode & ^uint32(0777) != 0 || d.Access != "rw" {
				return fmt.Errorf("volume %s: invalid directory declaration", d.Name)
			}
		}
		for _, link := range d.Links {
			if !relativePath(link.Path) || link.Path == "." || !absolutePath(link.Target) || d.Access != "rw" {
				return fmt.Errorf("volume %s: invalid link declaration", d.Name)
			}
		}
	}
	for _, d := range p.Volumes {
		if err := d.validateOverlays(byName); err != nil {
			return err
		}
	}

	return device.StorageSlots(packs, disks)
}

func (d Definition) validateOverlays(byName map[string]Definition) error {
	occupied := map[string]bool{}
	for _, o := range d.Overlays {
		lower, ok := byName[o.Volume]
		if !ok || lower.Pack == nil || d.Exec && !lower.Exec || d.Disk == nil || d.Access != "rw" || d.Filesystem != "ext4" {
			return fmt.Errorf("volume %s: invalid overlay source", d.Name)
		}
		if !relativePath(o.Source) || !relativePath(o.Target) || o.Target == "." {
			return fmt.Errorf("volume %s: invalid overlay paths", d.Name)
		}
		for _, path := range []string{o.Target, o.Target + upperSuffix, o.Target + workSuffix} {
			for existing := range occupied {
				if path == existing || strings.HasPrefix(path, existing+"/") || strings.HasPrefix(existing, path+"/") {
					return fmt.Errorf("volume %s: overlapping overlays", d.Name)
				}
			}
			occupied[path] = true
		}
	}
	return nil
}
