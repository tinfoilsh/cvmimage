package volume

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestMountOptions(t *testing.T) {
	device := filepath.Join(t.TempDir(), "ext4")
	clean := make([]byte, 2048)
	binary.LittleEndian.PutUint16(clean[1024+0x38:], 0xef53)
	binary.LittleEndian.PutUint16(clean[1024+0x3a:], 1)
	if err := os.WriteFile(device, clean, 0600); err != nil {
		t.Fatal(err)
	}
	base := uintptr(unix.MS_NODEV | unix.MS_NOSUID)
	for _, tt := range []struct {
		fs, access string
		exec       bool
		flags      uintptr
		data       string
	}{
		{"erofs", "ro", false, base | unix.MS_RDONLY | unix.MS_NOEXEC, ""},
		{"erofs", "ro", true, base | unix.MS_RDONLY, ""},
		{"ext4", "ro", false, base | unix.MS_RDONLY | unix.MS_NOEXEC, "noload,errors=remount-ro"},
		{"ext4", "ro", true, base | unix.MS_RDONLY, "noload,errors=remount-ro"},
		{"ext4", "rw", false, base | unix.MS_NOEXEC, "errors=remount-ro"},
		{"ext4", "rw", true, base, "errors=remount-ro"},
	} {
		flags, data, err := mountOptions(device, tt.fs, tt.access, tt.exec)
		if err != nil || flags != tt.flags || data != tt.data {
			t.Errorf("%s/%s exec=%t: flags=%#x data=%q err=%v", tt.fs, tt.access, tt.exec, flags, data, err)
		}
	}
	for _, tt := range []struct{ fs, access string }{{"erofs", "rw"}, {"xfs", "ro"}, {"ext4", "unknown"}} {
		if _, _, err := mountOptions(device, tt.fs, tt.access, false); err == nil {
			t.Errorf("accepted %s/%s", tt.fs, tt.access)
		}
	}
	for _, bad := range [][]byte{clean[:1536], make([]byte, 2048)} {
		if err := os.WriteFile(device, bad, 0600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := mountOptions(device, "ext4", "ro", false); err == nil {
			t.Fatal("accepted incomplete or invalid ext4")
		}
	}
	clean[1024+0x60] = 4
	if err := os.WriteFile(device, clean, 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := mountOptions(device, "ext4", "ro", false); err == nil {
		t.Fatal("accepted read-only ext4 needing recovery")
	}
	if _, _, err := mountOptions(device, "ext4", "rw", false); err != nil {
		t.Fatalf("prevented writable recovery: %v", err)
	}
}
