package volume

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

// mountOptions checks filesystem policy before mounting the device.
// Read-only ext4 must be clean: ro alone can replay the journal, while noload
// alone can expose an inconsistent filesystem.
func mountOptions(device, fs, access string, executable bool) (uintptr, string, error) {
	if access != "ro" && access != "rw" {
		return 0, "", fmt.Errorf("unsupported filesystem access %q", access)
	}
	flags := uintptr(unix.MS_NODEV | unix.MS_NOSUID)
	if access == "ro" {
		flags |= unix.MS_RDONLY
	}
	if !executable {
		flags |= unix.MS_NOEXEC
	}
	switch fs {
	case "erofs":
		if access != "ro" {
			return 0, "", errors.New("erofs requires read-only access")
		}
		return flags, "", nil
	case "ext4":
		if access == "rw" {
			return flags, "errors=remount-ro", nil
		}
		f, err := os.Open(device)
		if err != nil {
			return 0, "", err
		}
		defer f.Close()
		if err := checkCleanExt4(f); err != nil {
			return 0, "", err
		}
		return flags, "noload,errors=remount-ro", nil
	default:
		return 0, "", fmt.Errorf("unsupported filesystem %q", fs)
	}
}

func checkCleanExt4(r io.ReaderAt) error {
	var super [1024]byte
	if _, err := r.ReadAt(super[:], 1024); err != nil {
		return err
	}
	defer clear(super[:])
	// Linux ext4_super_block: s_magic, s_state, s_feature_incompat,
	// s_last_orphan, and s_feature_ro_compat (ORPHAN_PRESENT).
	if binary.LittleEndian.Uint16(super[0x38:]) != 0xef53 {
		return errors.New("volume does not contain ext4")
	}
	if binary.LittleEndian.Uint16(super[0x3a:]) != 1 ||
		binary.LittleEndian.Uint32(super[0x60:])&4 != 0 ||
		binary.LittleEndian.Uint32(super[0xe8:]) != 0 ||
		binary.LittleEndian.Uint32(super[0x64:])&0x10000 != 0 {
		return errors.New("read-only ext4 requires a clean filesystem; recover with writable access first")
	}
	return nil
}
