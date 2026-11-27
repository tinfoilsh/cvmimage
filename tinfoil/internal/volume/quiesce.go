package volume

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

const mountInfoPath = "/proc/self/mountinfo"

// Quiesce flushes every mounted volume and takes it off line before the guest
// powers off. Call it after every workload and service that could write to a
// volume has exited.
//
// The workspace volume sits on dm-integrity in unjournaled (D) mode, where a
// sector's data and its tag are separate writes. A write still in flight when
// the guest powers off is torn: its tag no longer matches, and the block reads
// back as EIO from then on. When that block is ext4 metadata that the mount
// reads before journal replay, such as the group descriptor table, the volume
// can never be mounted again, although the ext4 journal holds a good copy.
// reboot(2) does not sync or unmount, so the flush has to happen here.
func Quiesce() error {
	unix.Sync()
	targets, err := volumeMounts(mountInfoPath, dataRoot)
	var errs []error
	if err != nil {
		errs = append(errs, err)
	}
	for _, target := range targets {
		if err := unix.Unmount(target, 0); err != nil {
			// Something still holds it. A read-only remount still writes back
			// ext4's dirty metadata and finishes its journal checkpoint.
			if remountErr := unix.Mount("", target, "", unix.MS_REMOUNT|unix.MS_RDONLY, ""); remountErr != nil {
				errs = append(errs, fmt.Errorf("quiescing %s: unmount: %w; read-only remount: %v", target, err, remountErr))
			}
		}
	}
	unix.Sync()
	return errors.Join(errs...)
}

// volumeMounts lists the mount points at or below root, deepest first, so an
// overlay comes off before the volume it sits on.
func volumeMounts(path, root string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return parseVolumeMounts(file, root)
}

func parseVolumeMounts(r io.Reader, root string) ([]string, error) {
	root = filepath.Clean(root)
	seen := map[string]bool{}
	var targets []string
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 5 {
			continue
		}
		target := unescapeMountPath(fields[4])
		if target != root && !strings.HasPrefix(target, root+"/") {
			continue
		}
		if !seen[target] {
			seen[target] = true
			targets = append(targets, target)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	sort.SliceStable(targets, func(i, j int) bool {
		return strings.Count(targets[i], "/") > strings.Count(targets[j], "/")
	})
	return targets, nil
}

// unescapeMountPath undoes the octal escapes (\040 for a space) that the
// kernel writes into mountinfo paths.
func unescapeMountPath(field string) string {
	if !strings.Contains(field, `\`) {
		return field
	}
	var out strings.Builder
	for i := 0; i < len(field); i++ {
		if field[i] == '\\' && i+3 < len(field) {
			if value, err := strconv.ParseUint(field[i+1:i+4], 8, 8); err == nil {
				out.WriteByte(byte(value))
				i += 3
				continue
			}
		}
		out.WriteByte(field[i])
	}
	return out.String()
}
