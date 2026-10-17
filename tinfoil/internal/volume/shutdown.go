package volume

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"

	"golang.org/x/sys/unix"

	"tinfoil/internal/devicemapper"
)

// Shutdown makes mounted volumes durable after PID 1 has stopped all services
// and the debug console. In direct integrity mode, sync alone can leave tags
// buffered beneath ext4; stop filesystem writes before flushing the device.
func Shutdown() error {
	data, err := os.ReadFile("/proc/self/mounts")
	if err != nil {
		return err
	}
	var mounts [][]string
	unescape := strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`)
	for line := range strings.SplitSeq(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		fields[0] = unescape.Replace(fields[0])
		fields[1] = unescape.Replace(fields[1])
		if strings.HasPrefix(fields[1], dataRoot+"/") && (fields[2] == "overlay" || fields[2] == "ext4") {
			mounts = append(mounts, fields)
		}
	}
	// Overlay mounts hold their upper filesystem writable. Remove children
	// before parents, including stacked mounts at the same path.
	slices.Reverse(mounts)
	slices.SortStableFunc(mounts, func(a, b []string) int {
		return len(b[1]) - len(a[1])
	})
	var result error
	for _, mount := range mounts {
		source, target, fstype := mount[0], mount[1], mount[2]
		if fstype == "overlay" {
			// A lazy unmount would leave writes active in surviving namespaces.
			if err := unix.Unmount(target, 0); err != nil {
				result = errors.Join(result, fmt.Errorf("unmount overlay %s: %w", target, err))
			}
			continue
		}
		// Remount the whole filesystem, not just a bind mount. No services
		// remain, so executable volumes can also become noexec at shutdown.
		flags := uintptr(unix.MS_REMOUNT | unix.MS_RDONLY | unix.MS_NODEV | unix.MS_NOSUID | unix.MS_NOEXEC)
		if err := unix.Mount("", target, "", flags, ""); err != nil {
			result = errors.Join(result, fmt.Errorf("remount volume %s read-only: %w", target, err))
			continue
		}
		device, err := devicemapper.OpenBlockDevice(source)
		if err != nil {
			result = errors.Join(result, fmt.Errorf("open volume %s for flush: %w", source, err))
			continue
		}
		// Flush after ext4 has finished its final journal/superblock writes.
		err = errors.Join(device.Sync(), device.Close())
		if err != nil {
			result = errors.Join(result, fmt.Errorf("flush volume %s: %w", source, err))
		}
	}
	return result
}
