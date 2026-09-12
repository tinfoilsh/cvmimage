package volume

// Formatting and sparse initialization are ported from cvmimage commit
// 34c964d (tinfoil/cmd/volumeworker), with preparation inside the capability-free
// formatter child. Keep its layout probe and mkfs arguments together.
import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
)

const (
	mkfsPath          = "/usr/sbin/mkfs.ext4"
	backupHeading     = "Superblock backups stored on blocks:"
	formatEdgeBytes   = 8 << 20
	formatBackupBytes = 4 << 20
	formatChunkBytes  = 1 << 20
	formatBlockBytes  = 4096
)

func mkfsArgs(owner int) []string {
	// root_owner hands the volume to the login account. root_perms adds group
	// write and setgid, because the container writing this tree runs as uid 0
	// with the volume gid and no CAP_DAC_OVERRIDE, and new directories have to
	// stay in the group as it grows. mkfs has to set both: it writes the root
	// inode directly, whereas a chmod afterwards would need CAP_FOWNER, which
	// this formatter has just dropped.
	root := fmt.Sprintf("root_owner=%d:%d,root_perms=2775", owner, owner)
	// Nothing is left to first use: dm-integrity holds no tag for a block that was
	// never written, so a lazy table or journal reads back as an I/O error.
	return []string{
		mkfsPath, "-F",
		"-b", strconv.Itoa(formatBlockBytes),
		"-E", root + ",lazy_itable_init=0,lazy_journal_init=0",
	}
}

// prepareFormat writes a tag over every block mkfs reads, leaving the rest of
// the volume unwritten so its image stays sparse.
func prepareFormat(node string, owner int) error {
	backups, err := backupSuperblocks(node, owner)
	if err != nil {
		return err
	}
	device, err := os.OpenFile(node, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer device.Close()
	size, err := device.Seek(0, io.SeekEnd)
	if err != nil {
		return err
	}
	zeros := make([]byte, formatChunkBytes)
	write := func(offset, length int64) error {
		if offset < 0 {
			length += offset
			offset = 0
		}
		if offset+length > size {
			length = size - offset
		}
		for length > 0 {
			chunk := min(length, int64(len(zeros)))
			if _, err := device.WriteAt(zeros[:chunk], offset); err != nil {
				return err
			}
			offset += chunk
			length -= chunk
		}
		return nil
	}
	if err := write(0, formatEdgeBytes); err != nil {
		return err
	}
	if err := write(size-formatEdgeBytes, formatEdgeBytes); err != nil {
		return err
	}
	for _, block := range backups {
		if err := write(int64(block)*formatBlockBytes, formatBackupBytes); err != nil {
			return err
		}
	}
	return device.Sync()
}

// backupSuperblocks asks mkfs where the backups will land. The dry run writes
// nothing and reports read errors it works around, so only stdout matters.
func backupSuperblocks(node string, owner int) ([]uint64, error) {
	output, _ := exec.Command(mkfsPath, append(mkfsArgs(owner)[1:], "-n", node)...).Output()
	fields := strings.Fields(strings.ReplaceAll(backupList(string(output)), ",", " "))
	blocks := make([]uint64, 0, len(fields))
	for _, field := range fields {
		block, err := strconv.ParseUint(field, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("unexpected block %q in the mkfs layout", field)
		}
		blocks = append(blocks, block)
	}
	if len(blocks) == 0 {
		return nil, errors.New("mkfs reported no backup superblocks")
	}
	return blocks, nil
}

// backupList reads the blocks under the heading, which mkfs wraps over as many
// indented lines as it needs and closes with a blank one.
func backupList(output string) string {
	_, rest, found := strings.Cut(output, backupHeading)
	if !found {
		return ""
	}
	var list strings.Builder
	for index, line := range strings.Split(rest, "\n") {
		// Index 0 trails the heading on its own line, blank or not.
		if index > 0 && strings.TrimSpace(line) == "" {
			break
		}
		list.WriteString(line)
		list.WriteByte(' ')
	}
	return list.String()
}

// FormatExt4 prepares authenticated sectors and replaces the formatter process
// with mkfs. Its caller must validate the device and owner and drop capabilities
// before entering, since the layout probe also executes mkfs.
func FormatExt4(node string, owner int) error {
	if err := prepareFormat(node, owner); err != nil {
		return err
	}
	return syscall.Exec(mkfsPath, append(mkfsArgs(owner), "-q", node), []string{})
}
