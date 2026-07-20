package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIsHex64(t *testing.T) {
	valid := strings.Repeat("a", 64)
	if !isHex64(valid) {
		t.Fatalf("expected valid roothash")
	}
	for _, value := range []string{
		valid[:63],
		valid + "0",
		"0123456789abcdefABCDEF0123456789abcdefABCDEF0123456789abcdez",
	} {
		if isHex64(value) {
			t.Fatalf("expected %q to be invalid", value)
		}
	}
}

func TestSplitRoothashAndGUID(t *testing.T) {
	roothash := "0123456789abcdef0123456789abcdefabcDEF0123456789ABCDef0123456789"
	root, verity := splitRoothash(roothash)
	if root != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("unexpected root half %q", root)
	}
	if verity != "abcDEF0123456789ABCDef0123456789" {
		t.Fatalf("unexpected verity half %q", verity)
	}

	if got := guidFromHex32(root); got != "01234567-89ab-cdef-0123-456789abcdef" {
		t.Fatalf("unexpected root guid %q", got)
	}
	if got := guidFromHex32(verity); got != "abcdef01-2345-6789-abcd-ef0123456789" {
		t.Fatalf("unexpected verity guid %q", got)
	}
}

func TestParseVeritySuperblock(t *testing.T) {
	superblock := testVeritySuperblock()
	metadata, err := parseVeritySuperblock(superblock)
	if err != nil {
		t.Fatalf("parseVeritySuperblock: %v", err)
	}
	if metadata.hashType != 1 ||
		metadata.dataBlocks != 786432 ||
		metadata.dataBlockSize != 4096 ||
		metadata.hashBlockSize != 4096 ||
		metadata.hashStartBlock != 1 ||
		metadata.hashAlgorithm != "sha256" ||
		!bytes.Equal(metadata.salt, []byte{
			0xb0, 0x46, 0x3b, 0x7a, 0x99, 0xb5, 0x5b, 0xdd,
			0x00, 0x0b, 0x6d, 0x41, 0x8f, 0xf3, 0x7d, 0x7d,
			0x3a, 0x73, 0xf2, 0xa2, 0x15, 0x3d, 0xf7, 0x42,
			0xc8, 0x99, 0x6f, 0xc1, 0x7e, 0x47, 0x53, 0xf8,
		}) {
		t.Fatalf("unexpected metadata: %+v", metadata)
	}
}

func TestParseVeritySuperblockRejectsInvalidMetadata(t *testing.T) {
	for name, mutate := range map[string]func([]byte){
		"short": func(superblock []byte) {
			clear(superblock[8:])
		},
		"signature": func(superblock []byte) {
			superblock[0] = 'x'
		},
		"version": func(superblock []byte) {
			binary.LittleEndian.PutUint32(superblock[8:12], 2)
		},
		"hash type": func(superblock []byte) {
			binary.LittleEndian.PutUint32(superblock[12:16], 2)
		},
		"algorithm": func(superblock []byte) {
			superblock[32] = 0
		},
		"block size": func(superblock []byte) {
			binary.LittleEndian.PutUint32(superblock[64:68], 513)
		},
		"data blocks": func(superblock []byte) {
			binary.LittleEndian.PutUint64(superblock[72:80], 0)
		},
		"salt size": func(superblock []byte) {
			binary.LittleEndian.PutUint16(superblock[80:82], 257)
		},
	} {
		t.Run(name, func(t *testing.T) {
			superblock := testVeritySuperblock()
			mutate(superblock)
			if name == "short" {
				superblock = superblock[:64]
			}
			if _, err := parseVeritySuperblock(superblock); err == nil {
				t.Fatalf("expected invalid superblock to fail")
			}
		})
	}
}

func TestValidVerityBlockSize(t *testing.T) {
	for _, size := range []uint32{512, 1024, 4096, 512 * 1024} {
		if !validVerityBlockSize(size) {
			t.Fatalf("expected %d to be valid", size)
		}
	}
	for _, size := range []uint32{0, 511, 513, 1000, 1024 * 1024} {
		if validVerityBlockSize(size) {
			t.Fatalf("expected %d to be invalid", size)
		}
	}
}

func TestParseModuleManifest(t *testing.T) {
	modules, err := parseModuleManifest([]byte(`
# measured-root modules
/usr/lib/modules/7.0.0-15-generic/kernel/drivers/md/dm-bufio.ko
/usr/lib/modules/7.0.0-15-generic/kernel/drivers/md/dm-verity.ko
`))
	if err != nil {
		t.Fatalf("parseModuleManifest: %v", err)
	}
	if want := []string{
		"/usr/lib/modules/7.0.0-15-generic/kernel/drivers/md/dm-bufio.ko",
		"/usr/lib/modules/7.0.0-15-generic/kernel/drivers/md/dm-verity.ko",
	}; !stringSlicesEqual(modules, want) {
		t.Fatalf("unexpected modules: got %v want %v", modules, want)
	}
}

func TestParseModuleManifestRejectsBroadModuleSurface(t *testing.T) {
	for name, manifest := range map[string]string{
		"empty":           "",
		"relative":        "usr/lib/modules/7.0.0-15-generic/kernel/drivers/md/dm-verity.ko\n",
		"escape":          "/usr/lib/modules/7.0.0-15-generic/kernel/drivers/md/../dm-verity.ko\n",
		"wrong directory": "/usr/lib/modules/7.0.0-15-generic/kernel/drivers/net/veth.ko\n",
		"wrong module":    "/usr/lib/modules/7.0.0-15-generic/kernel/drivers/md/dm-crypt.ko\n",
		"compressed name": "/usr/lib/modules/7.0.0-15-generic/kernel/drivers/md/dm-verity.ko.zst\n",
		"wrong order": strings.Join([]string{
			"/usr/lib/modules/7.0.0-15-generic/kernel/drivers/md/dm-verity.ko",
			"/usr/lib/modules/7.0.0-15-generic/kernel/drivers/md/dm-bufio.ko",
			"",
		}, "\n"),
		"duplicate": strings.Join([]string{
			"/usr/lib/modules/7.0.0-15-generic/kernel/drivers/md/dm-bufio.ko",
			"/usr/lib/modules/7.0.0-15-generic/kernel/drivers/md/dm-bufio.ko",
			"",
		}, "\n"),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseModuleManifest([]byte(manifest)); err == nil {
				t.Fatalf("expected manifest to be rejected")
			}
		})
	}

	var tooMany strings.Builder
	for range maxInitrdModules + 1 {
		tooMany.WriteString("/usr/lib/modules/7.0.0-15-generic/kernel/drivers/md/dm-bufio.ko\n")
	}
	if _, err := parseModuleManifest([]byte(tooMany.String())); err == nil {
		t.Fatalf("expected too many modules to be rejected")
	}
}

func TestCmdlineValueFrom(t *testing.T) {
	value, err := cmdlineValueFrom("console=hvc0 roothash=abcd tinfoil-initrd-modules=builtin", initrdModuleModeKey)
	if err != nil {
		t.Fatalf("cmdlineValueFrom: %v", err)
	}
	if value != initrdModuleBuiltinMode {
		t.Fatalf("mode = %q, want %q", value, initrdModuleBuiltinMode)
	}

	value, err = cmdlineValueFrom("tinfoil-initrd-modules=manifest roothash=abcd", initrdModuleModeKey)
	if err != nil {
		t.Fatalf("cmdlineValueFrom manifest: %v", err)
	}
	if value != initrdModuleManifestMode {
		t.Fatalf("mode = %q, want %q", value, initrdModuleManifestMode)
	}

	if _, err := cmdlineValueFrom("console=hvc0", initrdModuleModeKey); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing mode error = %v, want os.ErrNotExist", err)
	}
}

func TestInitrdModuleModeFromDefaultsToBuiltIn(t *testing.T) {
	value, err := initrdModuleModeFrom("console=hvc0 roothash=abcd")
	if err != nil {
		t.Fatalf("initrdModuleModeFrom: %v", err)
	}
	if value != initrdModuleBuiltinMode {
		t.Fatalf("mode = %q, want %q", value, initrdModuleBuiltinMode)
	}
}

func TestInitrdModuleModeFromRequiresExplicitManifest(t *testing.T) {
	value, err := initrdModuleModeFrom("tinfoil-initrd-modules=manifest roothash=abcd")
	if err != nil {
		t.Fatalf("initrdModuleModeFrom manifest: %v", err)
	}
	if value != initrdModuleManifestMode {
		t.Fatalf("mode = %q, want %q", value, initrdModuleManifestMode)
	}
}

func TestInitrdModuleModeFromRejectsUnsupportedValues(t *testing.T) {
	for _, cmdline := range []string{
		"tinfoil-initrd-modules= roothash=abcd",
		"tinfoil-initrd-modules=auto roothash=abcd",
	} {
		t.Run(cmdline, func(t *testing.T) {
			if _, err := initrdModuleModeFrom(cmdline); err == nil {
				t.Fatalf("expected unsupported mode to fail")
			}
		})
	}
}

func TestDeviceMapperIoctlConstants(t *testing.T) {
	if dmIoctlSize != 312 || dmTargetSpecSize != 40 {
		t.Fatalf("unexpected dm ioctl layout: ioctl=%d target=%d", dmIoctlSize, dmTargetSpecSize)
	}
	for name, tc := range map[string]struct {
		got  uintptr
		want uintptr
	}{
		"version":    {dmVersionIOCTL, 0xc138fd00},
		"create":     {dmDevCreateIOCTL, 0xc138fd03},
		"resume":     {dmDevSuspendIOCTL, 0xc138fd06},
		"status":     {dmDevStatusIOCTL, 0xc138fd07},
		"table load": {dmTableLoadIOCTL, 0xc138fd09},
	} {
		t.Run(name, func(t *testing.T) {
			if tc.got != tc.want {
				t.Fatalf("unexpected ioctl number: got %#x want %#x", tc.got, tc.want)
			}
		})
	}
}

func TestDeviceMapperTableLoadBuffer(t *testing.T) {
	buf, err := dmTableLoadBuffer("root", 6291456, "verity", "1 8:1 8:2 4096 4096 786432 1 sha256 abcdef 012345")
	if err != nil {
		t.Fatalf("dmTableLoadBuffer: %v", err)
	}
	if binary.LittleEndian.Uint32(buf[0:4]) != 4 ||
		binary.LittleEndian.Uint32(buf[12:16]) != uint32(len(buf)) ||
		binary.LittleEndian.Uint32(buf[16:20]) != dmIoctlDataStart ||
		binary.LittleEndian.Uint32(buf[20:24]) != 1 ||
		binary.LittleEndian.Uint32(buf[28:32]) != dmReadOnlyFlag|dmExistsFlag {
		t.Fatalf("unexpected dm ioctl header")
	}
	if got := cString(buf[dmNameOffset : dmNameOffset+128]); got != "root" {
		t.Fatalf("unexpected dm name %q", got)
	}

	spec := buf[dmIoctlSize : dmIoctlSize+dmTargetSpecSize]
	if binary.LittleEndian.Uint64(spec[0:8]) != 0 ||
		binary.LittleEndian.Uint64(spec[8:16]) != 6291456 {
		t.Fatalf("unexpected target range")
	}
	next := binary.LittleEndian.Uint32(spec[20:24])
	if next%dmTargetSpecAlign != 0 || int(next) != len(buf)-dmIoctlSize {
		t.Fatalf("unexpected next target offset %d for len %d", next, len(buf))
	}
	if got := cString(spec[24:40]); got != "verity" {
		t.Fatalf("unexpected target type %q", got)
	}
	if got := cString(buf[dmIoctlSize+dmTargetSpecSize:]); got != "1 8:1 8:2 4096 4096 786432 1 sha256 abcdef 012345" {
		t.Fatalf("unexpected target params %q", got)
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

func testVeritySuperblock() []byte {
	superblock := make([]byte, veritySuperblockLen)
	copy(superblock[0:8], []byte("verity\x00\x00"))
	binary.LittleEndian.PutUint32(superblock[8:12], 1)
	binary.LittleEndian.PutUint32(superblock[12:16], 1)
	copy(superblock[16:32], []byte{
		0x27, 0xe6, 0xe0, 0x0d, 0x02, 0x58, 0x44, 0xb3,
		0x81, 0xbb, 0x12, 0xa5, 0x74, 0x22, 0x44, 0xe5,
	})
	copy(superblock[32:64], []byte("sha256"))
	binary.LittleEndian.PutUint32(superblock[64:68], 4096)
	binary.LittleEndian.PutUint32(superblock[68:72], 4096)
	binary.LittleEndian.PutUint64(superblock[72:80], 786432)
	binary.LittleEndian.PutUint16(superblock[80:82], 32)
	copy(superblock[88:120], []byte{
		0xb0, 0x46, 0x3b, 0x7a, 0x99, 0xb5, 0x5b, 0xdd,
		0x00, 0x0b, 0x6d, 0x41, 0x8f, 0xf3, 0x7d, 0x7d,
		0x3a, 0x73, 0xf2, 0xa2, 0x15, 0x3d, 0xf7, 0x42,
		0xc8, 0x99, 0x6f, 0xc1, 0x7e, 0x47, 0x53, 0xf8,
	})
	return superblock
}

func cString(buf []byte) string {
	if index := bytes.IndexByte(buf, 0); index >= 0 {
		buf = buf[:index]
	}
	return string(buf)
}

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
