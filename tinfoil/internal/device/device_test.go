package device

import (
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func withFixture(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	oldSysBlockDir := sysBlockDir
	oldDevDir := devDir
	oldGroupFile := groupFile
	oldTimeout := deviceWaitTimeout
	oldDelay := deviceWaitDelay
	sysBlockDir = filepath.Join(root, "sys", "block")
	devDir = filepath.Join(root, "dev")
	groupFile = filepath.Join(root, "etc", "group")
	deviceWaitTimeout = time.Millisecond
	deviceWaitDelay = time.Millisecond
	t.Cleanup(func() {
		sysBlockDir = oldSysBlockDir
		devDir = oldDevDir
		groupFile = oldGroupFile
		deviceWaitTimeout = oldTimeout
		deviceWaitDelay = oldDelay
	})
	mustMkdir(t, sysBlockDir)
	mustMkdir(t, devDir)
	mustMkdir(t, filepath.Dir(groupFile))
	mustWrite(t, groupFile, "disk:x:6:\nvideo:x:44:\nrender:x:109:\n")
	return sysBlockDir, devDir
}

func TestDiskBySCSISerialFromSerialFile(t *testing.T) {
	sysBlock, dev := withFixture(t)
	mustMkdir(t, filepath.Join(sysBlock, "sdb", "device"))
	mustWrite(t, filepath.Join(sysBlock, "sdb", "device", "serial"), "tinfoil-config\n")
	mustWrite(t, filepath.Join(dev, "sdb"), "")

	got, err := DiskBySCSISerial(ConfigDiskSerial)
	if err != nil {
		t.Fatalf("DiskBySCSISerial: %v", err)
	}
	if got != filepath.Join(dev, "sdb") {
		t.Fatalf("path mismatch: got %s", got)
	}
}

func TestDiskBySCSISerialFollowsSysfsBlockSymlink(t *testing.T) {
	sysBlock, dev := withFixture(t)
	target := filepath.Join(filepath.Dir(sysBlock), "devices", "pci0000:00", "sdb")
	mustMkdir(t, filepath.Join(target, "device"))
	mustWrite(t, filepath.Join(target, "device", "serial"), "tinfoil-config\n")
	mustSymlink(t, target, filepath.Join(sysBlock, "sdb"))
	mustWrite(t, filepath.Join(dev, "sdb"), "")

	got, err := DiskBySCSISerial(ConfigDiskSerial)
	if err != nil {
		t.Fatalf("DiskBySCSISerial: %v", err)
	}
	if got != filepath.Join(dev, "sdb") {
		t.Fatalf("path mismatch: got %s", got)
	}
}

func TestDiskBySCSISerialFromVPDPage80(t *testing.T) {
	sysBlock, dev := withFixture(t)
	serial := "tinfoil-ext-config"
	mustMkdir(t, filepath.Join(sysBlock, "sdc", "device"))
	mustWriteBytes(t, filepath.Join(sysBlock, "sdc", "device", "vpd_pg80"), append([]byte{0, 0x80, 0, byte(len(serial))}, []byte(serial)...))
	mustWrite(t, filepath.Join(dev, "sdc"), "")

	got, err := DiskBySCSISerial(ExternalConfigDiskSerial)
	if err != nil {
		t.Fatalf("DiskBySCSISerial: %v", err)
	}
	if got != filepath.Join(dev, "sdc") {
		t.Fatalf("path mismatch: got %s", got)
	}
}

func TestDiskBySCSISerialFromVPDPage83(t *testing.T) {
	sysBlock, dev := withFixture(t)
	mustMkdir(t, filepath.Join(sysBlock, "sdd", "device"))
	mustWriteBytes(t, filepath.Join(sysBlock, "sdd", "device", "vpd_pg83"), vpdPage83("QEMU HARDDISK tinfoil-config"))
	mustWrite(t, filepath.Join(dev, "sdd"), "")

	got, err := DiskBySCSISerial(ConfigDiskSerial)
	if err != nil {
		t.Fatalf("DiskBySCSISerial: %v", err)
	}
	if got != filepath.Join(dev, "sdd") {
		t.Fatalf("path mismatch: got %s", got)
	}
}

func TestDiskBySCSISerialNotFoundIncludesCandidateIdentity(t *testing.T) {
	sysBlock, dev := withFixture(t)
	addDisk(t, sysBlock, dev, "sdb", "not-the-config-disk")

	_, err := DiskBySCSISerial(ConfigDiskSerial)
	if err == nil {
		t.Fatal("DiskBySCSISerial unexpectedly succeeded")
	}
	got := err.Error()
	for _, want := range []string{"candidates:", "sdb", "not-the-config-disk", "node=ready"} {
		if !strings.Contains(got, want) {
			t.Fatalf("error %q does not contain %q", got, want)
		}
	}
}

func TestModelDeviceByPARTUUIDScopesToModelwrapDisk(t *testing.T) {
	sysBlock, dev := withFixture(t)
	partuuid := "2738a049-90ca-5450-8769-3280c6c517fe"
	addDisk(t, sysBlock, dev, "sdb", "not-a-modelwrap")
	addDisk(t, sysBlock, dev, "sdd", "tinfoil-modelwrap1")
	addPartition(t, sysBlock, dev, "sdb", "sdb1", partuuid)
	addPartition(t, sysBlock, dev, "sdd", "sdd1", partuuid)

	got, err := ModelDeviceByPARTUUID(strings.ToUpper(partuuid))
	if err != nil {
		t.Fatalf("ModelDeviceByPARTUUID: %v", err)
	}
	if got != filepath.Join(dev, "sdd1") {
		t.Fatalf("path mismatch: got %s", got)
	}
}

func TestModelDeviceByPARTUUIDScopesToModelwrapVPDPage83Disk(t *testing.T) {
	sysBlock, dev := withFixture(t)
	partuuid := "2738a049-90ca-5450-8769-3280c6c517fe"
	addDisk(t, sysBlock, dev, "sdb", "not-a-modelwrap")
	addDiskVPD83(t, sysBlock, dev, "sdd", "QEMU HARDDISK tinfoil-modelwrap1")
	addPartition(t, sysBlock, dev, "sdb", "sdb1", partuuid)
	addPartition(t, sysBlock, dev, "sdd", "sdd1", partuuid)

	got, err := ModelDeviceByPARTUUID(strings.ToUpper(partuuid))
	if err != nil {
		t.Fatalf("ModelDeviceByPARTUUID: %v", err)
	}
	if got != filepath.Join(dev, "sdd1") {
		t.Fatalf("path mismatch: got %s", got)
	}
}

func TestModelDeviceByFilesystemUUIDProbesOnlyModelwrapDevices(t *testing.T) {
	sysBlock, dev := withFixture(t)
	addDisk(t, sysBlock, dev, "sdb", "tinfoil-config")
	addPartition(t, sysBlock, dev, "sdb", "sdb1", "2738a049-90ca-5450-8769-3280c6c517fe")
	addDisk(t, sysBlock, dev, "sdd", "tinfoil-modelwrap1")
	addPartition(t, sysBlock, dev, "sdd", "sdd1", "2738a049-90ca-5450-8769-3280c6c517fe")

	uuid := "0eefa619-50b7-588f-a072-d405fb439d36"
	writeEROFSImage(t, filepath.Join(dev, "sdb1"), uuid)
	writeEROFSImage(t, filepath.Join(dev, "sdd1"), uuid)

	got, err := ModelDeviceByFilesystemUUID(uuid)
	if err != nil {
		t.Fatalf("ModelDeviceByFilesystemUUID: %v", err)
	}
	if got != filepath.Join(dev, "sdd1") {
		t.Fatalf("path mismatch: got %s", got)
	}
}

func TestFilesystemUUIDReadsEROFSSuperblock(t *testing.T) {
	_, dev := withFixture(t)
	path := filepath.Join(dev, "mwp")
	uuid := "0eefa619-50b7-588f-a072-d405fb439d36"
	writeEROFSImage(t, path, uuid)

	got, err := filesystemUUID(path)
	if err != nil {
		t.Fatalf("filesystemUUID: %v", err)
	}
	if got != uuid {
		t.Fatalf("uuid mismatch: got %s, want %s", got, uuid)
	}
}

func TestFilesystemUUIDReadsExtSuperblock(t *testing.T) {
	_, dev := withFixture(t)
	path := filepath.Join(dev, "legacy")
	uuid := "89abcdef-0123-4567-89ab-cdef01234567"
	writeExtImage(t, path, uuid)

	got, err := filesystemUUID(path)
	if err != nil {
		t.Fatalf("filesystemUUID: %v", err)
	}
	if got != uuid {
		t.Fatalf("uuid mismatch: got %s, want %s", got, uuid)
	}
}

func TestFilesystemUUIDRejectsUnknownPayload(t *testing.T) {
	_, dev := withFixture(t)
	path := filepath.Join(dev, "unknown")
	mustWrite(t, path, "not an erofs or ext superblock")

	if got, err := filesystemUUID(path); err == nil || got != "" {
		t.Fatalf("filesystemUUID unexpectedly succeeded: got=%q err=%v", got, err)
	}
}

func TestGroupID(t *testing.T) {
	_, _ = withFixture(t)
	got, err := groupID("render")
	if err != nil {
		t.Fatalf("groupID: %v", err)
	}
	if got != 109 {
		t.Fatalf("gid mismatch: got %d", got)
	}
}

func addDisk(t *testing.T, sysBlock, dev, name, serial string) {
	t.Helper()
	mustMkdir(t, filepath.Join(sysBlock, name, "device"))
	mustWrite(t, filepath.Join(sysBlock, name, "device", "serial"), serial+"\n")
	mustWrite(t, filepath.Join(sysBlock, name, "uevent"), "DEVNAME="+name+"\nDEVTYPE=disk\n")
	mustWrite(t, filepath.Join(dev, name), "")
}

func addDiskVPD83(t *testing.T, sysBlock, dev, name, identity string) {
	t.Helper()
	mustMkdir(t, filepath.Join(sysBlock, name, "device"))
	mustWriteBytes(t, filepath.Join(sysBlock, name, "device", "vpd_pg83"), vpdPage83(identity))
	mustWrite(t, filepath.Join(sysBlock, name, "uevent"), "DEVNAME="+name+"\nDEVTYPE=disk\n")
	mustWrite(t, filepath.Join(dev, name), "")
}

func addPartition(t *testing.T, sysBlock, dev, disk, name, partuuid string) {
	t.Helper()
	mustMkdir(t, filepath.Join(sysBlock, disk, name))
	mustWrite(t, filepath.Join(sysBlock, disk, name, "uevent"), "DEVNAME="+name+"\nDEVTYPE=partition\nPARTUUID="+partuuid+"\n")
	mustWrite(t, filepath.Join(dev, name), "")
}

func vpdPage83(identity string) []byte {
	payload := []byte(identity)
	descriptor := append([]byte{0x02, 0x01, 0x00, byte(len(payload))}, payload...)
	return append([]byte{0x00, 0x83, byte(len(descriptor) >> 8), byte(len(descriptor))}, descriptor...)
}

func mustMkdir(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0755); err != nil {
		t.Fatal(err)
	}
}

func mustWrite(t *testing.T, path, data string) {
	t.Helper()
	mustWriteBytes(t, path, []byte(data))
}

func mustWriteBytes(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}
}

func writeEROFSImage(t *testing.T, path, uuid string) {
	t.Helper()
	buf := make([]byte, filesystemProbeBytes)
	binary.LittleEndian.PutUint32(buf[erofsMagicOffset:], erofsMagic)
	copy(buf[erofsUUIDOffset:], mustParseUUID(t, uuid))
	mustWriteBytes(t, path, buf)
}

func writeExtImage(t *testing.T, path, uuid string) {
	t.Helper()
	buf := make([]byte, filesystemProbeBytes)
	binary.LittleEndian.PutUint16(buf[extMagicOffset:], extMagic)
	copy(buf[extUUIDOffset:], mustParseUUID(t, uuid))
	mustWriteBytes(t, path, buf)
}

func mustParseUUID(t *testing.T, uuid string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(strings.ReplaceAll(uuid, "-", ""))
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != uuidBytes {
		t.Fatalf("uuid byte length: got %d", len(raw))
	}
	return raw
}

func mustSymlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
}
