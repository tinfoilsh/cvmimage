//go:build integration

package devicemapper

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// This opt-in test creates its own temporary raw image. It does not accept an
// existing disk path. Malformed headers are tested only by the Go validator;
// no malformed configuration is submitted to the stock kernel.
func TestIntegrityKernelRoundTrip(t *testing.T) {
	if os.Getenv("TINFOIL_INTEGRITY_INTEGRATION") != "1" {
		t.Skip("set TINFOIL_INTEGRITY_INTEGRATION=1; requires root and loop/dm support")
	}
	if os.Geteuid() != 0 {
		t.Fatal("integration test requires root")
	}
	image, err := os.Create(filepath.Join(t.TempDir(), "fresh-volume.raw"))
	if err != nil {
		t.Fatal(err)
	}
	defer image.Close()
	t.Run("loop node repair", func(t *testing.T) {
		// These temporary device nodes are checked with stat, never opened.
		for _, mode := range []uint32{unix.S_IFCHR, unix.S_IFBLK} {
			path := filepath.Join(t.TempDir(), "node")
			for _, minor := range []uint32{3, 5, 5} { // missing, stale, already correct
				dev := unix.Mkdev(1, minor)
				if err := ensureLoopNode(path, mode, dev); err != nil {
					t.Fatal(err)
				}
				if !deviceNodeMatches(path, mode == unix.S_IFCHR, dev) {
					t.Fatal("loop node identity mismatch")
				}
			}
		}
		link := filepath.Join(t.TempDir(), "link")
		if err := os.Symlink(image.Name(), link); err != nil {
			t.Fatal(err)
		}
		for _, path := range []string{image.Name(), link} {
			if err := ensureLoopNode(path, unix.S_IFCHR, unix.Mkdev(1, 3)); err == nil {
				t.Fatal("non-device loop node accepted")
			}
			if _, err := os.Lstat(path); err != nil {
				t.Fatalf("non-device was removed: %v", err)
			}
		}
	})
	const imageBytes = 64 * 1024 * 1024
	if err := image.Truncate(imageBytes); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("losetup", "--find", "--show", image.Name()).CombinedOutput()
	if err != nil {
		t.Fatalf("attach test image: %v: %s", err, out)
	}
	rawPath := strings.TrimSpace(string(out))
	t.Cleanup(func() {
		if out, err := exec.Command("losetup", "--detach", rawPath).CombinedOutput(); err != nil {
			t.Errorf("detach test image: %v: %s", err, out)
		}
	})
	raw, err := OpenBlockDevice(rawPath)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if err := EnsureControlNode(); err != nil {
		t.Fatal(err)
	}
	control, err := OpenControl()
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	name := fmt.Sprintf("tinfoil-integrity-test-%d", os.Getpid())
	cryptName := name + "-crypt"
	integrityActive, cryptActive, reformatActive := false, false, false
	settle := func() {
		// The production CVM disables DM_UEVENT. A developer host may have
		// udev briefly opening fresh devices for probing, so let it finish.
		if path, err := exec.LookPath("udevadm"); err == nil {
			if out, err := exec.Command(path, "settle", "--timeout=5").CombinedOutput(); err != nil {
				t.Errorf("udev settle: %v: %s", err, out)
			}
		}
	}
	defer func() {
		settle()
		if reformatActive {
			if err := RemoveIntegrity(control, name+"-reformat"); err != nil {
				t.Error(err)
			}
		}
		if cryptActive {
			if err := Remove(control, cryptName); err != nil {
				t.Error(err)
			}
		}
		if integrityActive {
			if err := RemoveIntegrity(control, name); err != nil {
				t.Error(err)
			}
		}
	}()
	metadataKey := bytes.Repeat([]byte{0x31}, IntegrityKeyBytes)
	dataKey := bytes.Repeat([]byte{0x42}, AuthenticatedKeyBytes)
	activate := func(initialize bool) {
		t.Helper()
		if err := ActivateIntegrity(control, raw, name, metadataKey, initialize); err != nil {
			t.Fatalf("activate integrity (initialize=%v): %v", initialize, err)
		}
		integrityActive = true
		tags, err := OpenBlockDevice(MapperNode(name))
		if err != nil {
			t.Fatal(err)
		}
		defer tags.Close()
		if _, err := ActivateWritableCrypt(control, tags, cryptName, dataKey); err != nil {
			t.Fatal(err)
		}
		cryptActive = true
	}
	deactivate := func() {
		t.Helper()
		settle()
		if err := Remove(control, cryptName); err != nil {
			t.Fatal(err)
		}
		cryptActive = false
		if err := RemoveIntegrity(control, name); err != nil {
			t.Fatal(err)
		}
		integrityActive = false
	}
	activate(true)
	// The Go header builder must agree with the superblock produced by Linux,
	// including the random salt/MAC, bitmap granularity and capacity.
	header := make([]byte, integrityHeaderBytes)
	if err := unix.IoctlSetInt(int(raw.Fd()), unix.BLKFLSBUF, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.ReadAt(header, 0); err != nil {
		t.Fatal(err)
	}
	layout, err := fixedIntegrityLayout(imageBytes / 512)
	if err != nil {
		t.Fatal(err)
	}
	fixedHeader, err := fixedIntegrityHeader(header, metadataKey, layout)
	if err != nil || !bytes.Equal(header, fixedHeader) {
		t.Fatalf("kernel header does not match the fixed Go format: %v", err)
	}
	if layout != (integrityLayout{journalSectors: 1024, journalSections: 3, dataSectors: 128736, bitmapLog: 12}) {
		t.Fatalf("unexpected 64 MiB layout: %+v", layout)
	}
	if bytes.Equal(header[48:64], make([]byte, 16)) {
		t.Fatal("kernel did not generate a random format salt")
	}
	_, sectors, err := BlockDeviceInfo(MapperNode(name))
	if err != nil || sectors != layout.dataSectors {
		t.Fatalf("kernel capacity %d, expected %d: %v", sectors, layout.dataSectors, err)
	}
	// Reinitialization must not silently overwrite an existing fixed-format
	// volume, even though this implementation has no compatibility path.
	if err := ActivateIntegrity(control, raw, name+"-reformat", metadataKey, true); err == nil {
		reformatActive = true
		t.Fatal("reinitializing a nonblank volume was accepted")
	}
	payload := bytes.Repeat([]byte{0x57}, cryptSectorSizeBytes)
	writeBlock := func(offset int64) {
		t.Helper()
		file, err := os.OpenFile(MapperNode(cryptName), os.O_RDWR, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		if _, err := file.WriteAt(payload, offset); err != nil {
			t.Fatal(err)
		}
		if err := file.Sync(); err != nil {
			t.Fatal(err)
		}
	}
	readBlock := func(offset int64) {
		t.Helper()
		file, err := os.Open(MapperNode(cryptName))
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		got := make([]byte, len(payload))
		if _, err := file.ReadAt(got, offset); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatal("authenticated data round trip mismatch")
		}
	}
	last := int64(layout.dataSectors*512) - cryptSectorSizeBytes
	writeBlock(0)
	writeBlock(last)
	readBlock(0)
	readBlock(last)
	suspend := func(mapping string) {
		t.Helper()
		buf, err := baseBuffer(ioctlSize, mapping)
		if err != nil {
			t.Fatal(err)
		}
		setFlags(buf, existsFlag|1<<1) // DM_SUSPEND_FLAG
		if err := ioctl(control, devSuspendIOCTL, buf, 1); err != nil {
			t.Fatal(err)
		}
	}
	suspend(cryptName)
	suspend(name)
	// Assert that reads of the prefix use the fixed bytes after the disk
	// prefix changes. The altered bytes are never fed to dm-integrity.
	backing, err := OpenBlockDevice(MapperNode(IntegrityBackingName(name)))
	if err != nil {
		t.Fatal(err)
	}
	defer backing.Close()
	if _, err := image.WriteAt(make([]byte, integrityHeaderBytes), 0); err != nil {
		t.Fatal(err)
	}
	if err := image.Sync(); err != nil {
		t.Fatal(err)
	}
	if err := unix.IoctlSetInt(int(backing.Fd()), unix.BLKFLSBUF, 0); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, integrityHeaderBytes)
	if _, err := backing.ReadAt(got, 0); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, header) {
		t.Fatal("protected header changed with the raw prefix")
	}
	if err := backing.Close(); err != nil {
		t.Fatal(err)
	}
	// Resume explicitly exercises the kernel's superblock reread, still
	// served entirely by the trusted prefix despite the raw disk change.
	if err := resume(control, name, 0); err != nil {
		t.Fatal(err)
	}
	if err := resume(control, cryptName, 0); err != nil {
		t.Fatal(err)
	}
	readBlock(0)
	readBlock(last)
	if _, err := image.WriteAt(header, 0); err != nil {
		t.Fatal(err)
	}
	if err := image.Sync(); err != nil {
		t.Fatal(err)
	}
	deactivate()
	if err := ActivateIntegrity(control, raw, name, bytes.Repeat([]byte{0x32}, 32), false); err == nil {
		integrityActive = true
		t.Fatal("wrong metadata key accepted")
	}
	activate(false)
	readBlock(0)
	readBlock(last)
	settle()
	if err := Remove(control, cryptName); err != nil {
		t.Fatal(err)
	}
	cryptActive = false
	if err := Remove(control, name); err != nil {
		t.Fatal(err)
	}
	// An already-removed primary returns ENXIO, but must not skip the backing.
	if err := RemoveIntegrity(control, name); !errors.Is(err, unix.ENXIO) {
		t.Fatalf("expected missing primary error: %v", err)
	}
	for _, mapping := range []string{name, cryptName, IntegrityBackingName(name)} {
		if _, exists, err := Lookup(control, mapping); err != nil || exists {
			t.Fatalf("mapping leaked: %s: %v", mapping, err)
		}
	}
	integrityActive = false
}
