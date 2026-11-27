package volume

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/sys/unix"

	"tinfoil/internal/devicemapper"
)

// Shutdown runs after the services and debug console have stopped. The actual
// mounts include manual unlocks and exclude locked placeholder binds.
func Shutdown() error {
	mounts, err := os.ReadFile("/proc/self/mounts")
	if err != nil {
		return err
	}
	volumes, overlays := mountedVolumes(string(mounts))
	var result error
	for _, target := range slices.Backward(overlays) {
		if err := unix.Unmount(target, 0); err != nil {
			result = errors.Join(result, fmt.Errorf("unmounting overlay %s: %w", target, err))
		}
	}
	for _, target := range volumes {
		if err := closeVolume(target); err != nil {
			result = errors.Join(result, fmt.Errorf("closing %s: %w", target, err))
		}
	}
	return result
}

func mountedVolumes(mounts string) (volumes, overlays []string) {
	for line := range strings.SplitSeq(mounts, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		relative, ok := strings.CutPrefix(fields[1], dataRoot+"/")
		if !ok {
			continue
		}
		name, child, nested := strings.Cut(relative, "/")
		if !namePattern.MatchString(name) {
			continue
		}
		switch {
		case fields[2] == "ext4" && !nested:
			volumes = append(volumes, fields[1])
		case fields[2] == "overlay" && namePattern.MatchString(child):
			overlays = append(overlays, fields[1])
		}
	}
	return volumes, overlays
}

func closeVolume(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	if err := errors.Join(unix.Syncfs(int(dir.Fd())), dir.Close()); err != nil {
		return err
	}
	if err := unix.Unmount(path, 0); err != nil {
		return err
	}
	// Flush after ext4's final journal and superblock writes. Removing the
	// mappings also checks that no other mount or opener still holds them.
	name := mapperRoot + filepath.Base(path)
	device, err := devicemapper.OpenBlockDevice(devicemapper.MapperNode(name))
	if err != nil {
		return err
	}
	if err := errors.Join(device.Sync(), device.Close()); err != nil {
		return err
	}
	control, err := devicemapper.OpenControl()
	if err != nil {
		return err
	}
	defer control.Close()
	if err := devicemapper.Remove(control, name); err != nil {
		return err
	}
	return devicemapper.Remove(control, name+integritySuffix)
}
