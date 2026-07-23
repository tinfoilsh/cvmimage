package devicemapper

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func TestIoctlConstants(t *testing.T) {
	if ioctlSize != 312 || targetSpecSize != 40 {
		t.Fatalf("unexpected dm ioctl layout: ioctl=%d target=%d", ioctlSize, targetSpecSize)
	}
	for name, tc := range map[string]struct {
		got  uintptr
		want uintptr
	}{
		"version":    {versionIOCTL, 0xc138fd00},
		"create":     {devCreateIOCTL, 0xc138fd03},
		"remove":     {devRemoveIOCTL, 0xc138fd04},
		"resume":     {devSuspendIOCTL, 0xc138fd06},
		"status":     {devStatusIOCTL, 0xc138fd07},
		"table load": {tableLoadIOCTL, 0xc138fd09},
	} {
		t.Run(name, func(t *testing.T) {
			if tc.got != tc.want {
				t.Fatalf("unexpected ioctl number: got %#x want %#x", tc.got, tc.want)
			}
		})
	}
}

func TestCryptTable(t *testing.T) {
	key := bytes.Repeat([]byte{0xa5}, 64)
	params, err := CryptTable("8:17", key, 8192)
	if err != nil {
		t.Fatalf("CryptTable: %v", err)
	}
	want := "aes-xts-plain64 " + strings.Repeat("a5", 64) + " 0 8:17 0 1 sector_size:4096"
	if string(params) != want {
		t.Fatalf("params = %q, want %q", params, want)
	}
	if !bytes.Equal(key, bytes.Repeat([]byte{0xa5}, 64)) {
		t.Fatal("CryptTable modified caller key")
	}

	for name, tc := range map[string]struct {
		device string
		key    []byte
		length uint64
	}{
		"device":    {device: "8:17 bad", key: key, length: 8192},
		"key":       {device: "8:17", key: key[:32], length: 8192},
		"alignment": {device: "8:17", key: key, length: 8191},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := CryptTable(tc.device, tc.key, tc.length); err == nil {
				t.Fatal("invalid dm-crypt table accepted")
			}
		})
	}
}

func TestBlockDeviceInfoRejectsIndirectAndNonBlockPaths(t *testing.T) {
	dir := t.TempDir()
	regularPath := filepath.Join(dir, "regular")
	if err := os.WriteFile(regularPath, []byte("not a block device"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := BlockDeviceInfo(regularPath); err == nil || !strings.Contains(err.Error(), "not a direct block device") {
		t.Fatalf("regular file error = %v", err)
	}

	symlinkPath := filepath.Join(dir, "symlink")
	if err := os.Symlink(regularPath, symlinkPath); err != nil {
		t.Fatal(err)
	}
	if _, _, err := BlockDeviceInfo(symlinkPath); err == nil {
		t.Fatal("symlink accepted as a direct block device")
	}
}

func TestTableLoadBuffer(t *testing.T) {
	buf, err := tableLoadBuffer("root", 6291456, "verity", "1 8:1 8:2 4096 4096 786432 1 sha256 abcdef 012345")
	if err != nil {
		t.Fatalf("tableLoadBuffer: %v", err)
	}
	if binary.LittleEndian.Uint32(buf[0:4]) != 4 ||
		binary.LittleEndian.Uint32(buf[12:16]) != uint32(len(buf)) ||
		binary.LittleEndian.Uint32(buf[16:20]) != ioctlDataStart ||
		binary.LittleEndian.Uint32(buf[20:24]) != 1 ||
		binary.LittleEndian.Uint32(buf[28:32]) != readOnlyFlag|existsFlag {
		t.Fatalf("unexpected dm ioctl header")
	}
	if got := cString(buf[nameOffset : nameOffset+128]); got != "root" {
		t.Fatalf("unexpected dm name %q", got)
	}

	spec := buf[ioctlSize : ioctlSize+targetSpecSize]
	if binary.LittleEndian.Uint64(spec[0:8]) != 0 ||
		binary.LittleEndian.Uint64(spec[8:16]) != 6291456 {
		t.Fatalf("unexpected target range")
	}
	next := binary.LittleEndian.Uint32(spec[20:24])
	if next%targetSpecAlign != 0 || int(next) != len(buf)-ioctlSize {
		t.Fatalf("unexpected next target offset %d for len %d", next, len(buf))
	}
	if got := cString(spec[24:40]); got != "verity" {
		t.Fatalf("unexpected target type %q", got)
	}
	if got := cString(buf[ioctlSize+targetSpecSize:]); got != "1 8:1 8:2 4096 4096 786432 1 sha256 abcdef 012345" {
		t.Fatalf("unexpected target params %q", got)
	}
}

func TestTableLoadBufferRejectsEmbeddedNUL(t *testing.T) {
	for name, tc := range map[string]struct {
		targetType string
		params     string
	}{
		"target type": {targetType: "ver\x00ity", params: "valid"},
		"parameters":  {targetType: "verity", params: "valid\x00ignored"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := tableLoadBuffer("root", 1, tc.targetType, tc.params); err == nil {
				t.Fatal("embedded NUL accepted")
			}
		})
	}
}

func TestReadMajorMinor(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dev")
	if err := os.WriteFile(path, []byte("10:236\n"), 0644); err != nil {
		t.Fatal(err)
	}
	major, minor, err := readMajorMinor(path)
	if err != nil {
		t.Fatalf("readMajorMinor: %v", err)
	}
	if major != 10 || minor != 236 {
		t.Fatalf("unexpected major/minor %d:%d", major, minor)
	}
}

func TestDeviceNodeMatchesTypeAndDeviceNumber(t *testing.T) {
	info, err := os.Lstat("/dev/null")
	if err != nil {
		t.Skipf("/dev/null unavailable: %v", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("/dev/null stat has unexpected type")
	}
	if !deviceNodeMatches("/dev/null", true, stat.Rdev) {
		t.Fatal("matching character device rejected")
	}
	wrongDev := unix.Mkdev(unix.Major(stat.Rdev), unix.Minor(stat.Rdev)+1)
	if deviceNodeMatches("/dev/null", true, wrongDev) {
		t.Fatal("wrong device number accepted")
	}
	if deviceNodeMatches("/dev/null", false, stat.Rdev) {
		t.Fatal("character device accepted as block device")
	}

	link := filepath.Join(t.TempDir(), "null")
	if err := os.Symlink("/dev/null", link); err != nil {
		t.Fatal(err)
	}
	if deviceNodeMatches(link, true, stat.Rdev) {
		t.Fatal("symlink accepted as device node")
	}
}

func TestValidateName(t *testing.T) {
	for _, name := range []string{"root", "model.sha256-dead_beef+1"} {
		if err := validateName(name); err != nil {
			t.Fatalf("valid name %q rejected: %v", name, err)
		}
	}
	for _, name := range []string{"", "name/with/slash", strings.Repeat("x", maxNameLen+1)} {
		if err := validateName(name); err == nil {
			t.Fatalf("invalid name %q accepted", name)
		}
	}
}

func TestPutCStringAlwaysTerminates(t *testing.T) {
	buf := bytes.Repeat([]byte{0xff}, 4)
	putCString(buf, "longer-than-buffer")
	if !bytes.Equal(buf, []byte{'l', 'o', 'n', 0}) {
		t.Fatalf("putCString result = %v, want truncated NUL-terminated string", buf)
	}
}

func cString(buf []byte) string {
	if index := bytes.IndexByte(buf, 0); index >= 0 {
		buf = buf[:index]
	}
	return string(buf)
}
