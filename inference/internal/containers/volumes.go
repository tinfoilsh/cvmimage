package containers

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	config "github.com/tinfoilsh/tinfoil-config"
	"tinfoil/inference/internal/variant"
	"tinfoil/internal/volume"
)

func debugStorageBind(c Container, bind string, debug bool) bool {
	return debug && c.Name == config.ReservedDebugContainerName && (bind == "/run/docker.sock:/var/run/docker.sock" || bind == "/run/tinfoil/containers.sock:/run/tinfoil/containers.sock")
}
func storageDependencies(c Container, debug bool) ([]string, error) {
	names := slices.Clone(c.Models)
	for _, bind := range c.Volumes {
		if debugStorageBind(c, bind, debug) {
			continue
		}
		name, _, _, err := config.ParseVolumeMount(bind)
		if err != nil {
			return nil, err
		}
		names = append(names, name)
	}
	slices.Sort(names)
	return slices.Compact(names), nil
}
func storageBindings(c Container, ready volume.ReadyVolumes, debug bool) ([]string, error) {
	var result []string
	bindVolume := func(name, target, access string) error {
		source, ok := ready[name]
		if !ok {
			return fmt.Errorf("volume %q is not ready", name)
		}
		if !filepath.IsAbs(source.Path) || filepath.Clean(source.Path) != source.Path || source.Path == "/" || strings.ContainsAny(source.Path, "\x00\n\r:") {
			return fmt.Errorf("invalid source for volume %q", name)
		}
		if source.Access != "ro" && source.Access != "rw" {
			return fmt.Errorf("invalid access for volume %q", name)
		}
		mode := source.Access
		if access == "rw" && mode == "ro" {
			return fmt.Errorf("read-only volume %q cannot be writable", name)
		}
		if access == "ro" {
			mode = "ro"
		}
		result = append(result, source.Path+":"+target+":"+mode)
		return nil
	}
	for _, name := range c.Models {
		if err := bindVolume(name, filepath.Join(variant.ContainerModelsDir, name), "ro"); err != nil {
			return nil, err
		}
	}
	for _, bind := range c.Volumes {
		if debugStorageBind(c, bind, debug) {
			result = append(result, bind)
			continue
		}
		name, target, access, err := config.ParseVolumeMount(bind)
		if err != nil {
			return nil, err
		}
		if err := bindVolume(name, target, access); err != nil {
			return nil, err
		}
	}
	return result, nil
}
