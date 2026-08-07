package device

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

type deviceFixture struct {
	pci string
	sys string
	dev string
}

func withFixture(t *testing.T) deviceFixture {
	t.Helper()
	root := t.TempDir()
	fixture := deviceFixture{
		pci: filepath.Join(root, "sys/bus/pci/devices"),
		sys: filepath.Join(root, "sys/block"),
		dev: filepath.Join(root, "dev"),
	}
	for _, path := range []string{fixture.pci, fixture.sys, fixture.dev} {
		if err := os.MkdirAll(path, 0755); err != nil {
			t.Fatal(err)
		}
	}

	oldPCI, oldSys, oldDev := sysBusPCIDevices, sysBlockDir, devDir
	oldTimeout, oldDelay := deviceWaitTimeout, deviceWaitDelay
	sysBusPCIDevices, sysBlockDir, devDir = fixture.pci, fixture.sys, fixture.dev
	deviceWaitTimeout, deviceWaitDelay = 0, 0
	t.Cleanup(func() {
		sysBusPCIDevices, sysBlockDir, devDir = oldPCI, oldSys, oldDev
		deviceWaitTimeout, deviceWaitDelay = oldTimeout, oldDelay
	})
	return fixture
}

func TestConfigDiskUsesFixedController(t *testing.T) {
	fixture := withFixture(t)
	addPCIDisk(t, fixture, configDiskPCIAddress, "sda")

	got, err := ConfigDisk()
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(fixture.dev, "sda"); got != want {
		t.Fatalf("ConfigDisk() = %q, want %q", got, want)
	}
}

func TestRootPartitionsUseFixedControllerAndPositions(t *testing.T) {
	fixture := withFixture(t)
	addPCIDisk(t, fixture, rootDiskPCIAddress, "sda")
	addPartition(t, fixture, "sda", "sda1", rootDataPartition)
	addPartition(t, fixture, "sda", "sda2", rootVerityPartition)
	addPCIDisk(t, fixture, configDiskPCIAddress, "sdb")
	addPartition(t, fixture, "sdb", "sdb1", rootDataPartition)

	root, verity, err := RootPartitions()
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(fixture.dev, "sda1"); root != want {
		t.Fatalf("root partition = %q, want %q", root, want)
	}
	if want := filepath.Join(fixture.dev, "sda2"); verity != want {
		t.Fatalf("verity partition = %q, want %q", verity, want)
	}
}

func TestRootPartitionsRejectInvalidTopology(t *testing.T) {
	t.Run("wrong controller", func(t *testing.T) {
		fixture := withFixture(t)
		addPCIDisk(t, fixture, configDiskPCIAddress, "sda")
		addPartition(t, fixture, "sda", "sda1", rootDataPartition)
		addPartition(t, fixture, "sda", "sda2", rootVerityPartition)
		if _, _, err := RootPartitions(); err == nil {
			t.Fatal("root partitions below the wrong controller were accepted")
		}
	})
	t.Run("ambiguous controller", func(t *testing.T) {
		fixture := withFixture(t)
		addPCIDisk(t, fixture, rootDiskPCIAddress, "sda")
		addPCIDisk(t, fixture, rootDiskPCIAddress, "sdb")
		if _, _, err := RootPartitions(); err == nil {
			t.Fatal("ambiguous root controller was accepted")
		}
	})
	t.Run("missing partition", func(t *testing.T) {
		fixture := withFixture(t)
		addPCIDisk(t, fixture, rootDiskPCIAddress, "sda")
		addPartition(t, fixture, "sda", "sda1", rootDataPartition)
		if _, _, err := RootPartitions(); err == nil {
			t.Fatal("missing root verity partition was accepted")
		}
	})
	t.Run("extra partition", func(t *testing.T) {
		fixture := withFixture(t)
		addPCIDisk(t, fixture, rootDiskPCIAddress, "sda")
		addPartition(t, fixture, "sda", "sda1", rootDataPartition)
		addPartition(t, fixture, "sda", "sda2", rootVerityPartition)
		addPartition(t, fixture, "sda", "sda3", 3)
		if _, _, err := RootPartitions(); err == nil {
			t.Fatal("extra root partition was accepted")
		}
	})
}

func TestExternalConfigDiskUsesFixedController(t *testing.T) {
	fixture := withFixture(t)
	addPCIDisk(t, fixture, externalDiskPCIAddress, "sdb")

	got, err := ExternalConfigDisk()
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(fixture.dev, "sdb"); got != want {
		t.Fatalf("ExternalConfigDisk() = %q, want %q", got, want)
	}
}

func TestConfigDiskRejectsWrongOrAmbiguousTopology(t *testing.T) {
	t.Run("wrong controller", func(t *testing.T) {
		fixture := withFixture(t)
		addPCIDisk(t, fixture, "0000:00:04.0", "sda")
		if _, err := ConfigDisk(); err == nil {
			t.Fatal("ConfigDisk() accepted a disk below the root controller")
		}
	})
	t.Run("ambiguous controller", func(t *testing.T) {
		fixture := withFixture(t)
		addPCIDisk(t, fixture, configDiskPCIAddress, "sda")
		addPCIDisk(t, fixture, configDiskPCIAddress, "sdb")
		if _, err := ConfigDisk(); err == nil {
			t.Fatal("ConfigDisk() accepted an ambiguous controller")
		}
	})
}

func TestConfigDiskRejectsLegacySCSITopologyAndWrongSerial(t *testing.T) {
	t.Run("legacy SCSI shape", func(t *testing.T) {
		fixture := withFixture(t)
		mustMkdir(t, filepath.Join(fixture.pci, configDiskPCIAddress))
		mustWrite(t, filepath.Join(fixture.pci, configDiskPCIAddress, "vendor"), virtioPCIVendorID+"\n")
		mustWrite(t, filepath.Join(fixture.pci, configDiskPCIAddress, "device"), virtioBlkPCIDeviceID+"\n")
		mustMkdir(t, filepath.Join(fixture.pci, configDiskPCIAddress, "virtio0", "host0", "target0:0:0", "0:0:0:0", "block", "sda"))
		if _, err := ConfigDisk(); err == nil {
			t.Fatal("legacy SCSI topology was accepted")
		}
	})
	t.Run("wrong serial", func(t *testing.T) {
		fixture := withFixture(t)
		addPCIDisk(t, fixture, configDiskPCIAddress, "vda")
		mustWrite(t, filepath.Join(fixture.sys, "vda", "serial"), "wrong\n")
		if _, err := ConfigDisk(); err == nil {
			t.Fatal("wrong virtio-blk serial was accepted")
		}
	})
}

func TestModelDiskAndPartitionUseConfigOrder(t *testing.T) {
	fixture := withFixture(t)
	addPCIDisk(t, fixture, "0000:00:07.0", "sdc")
	partitionDir := filepath.Join(fixture.sys, "sdc", "sdc1")
	mustMkdir(t, partitionDir)
	mustWrite(t, filepath.Join(partitionDir, "partition"), "1\n")
	mustWrite(t, filepath.Join(fixture.dev, "sdc1"), "")

	disk, err := ModelDisk(0)
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(fixture.dev, "sdc"); disk != want {
		t.Fatalf("ModelDisk(0) = %q, want %q", disk, want)
	}
	partition, err := ModelPartition(0, 1)
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(fixture.dev, "sdc1"); partition != want {
		t.Fatalf("ModelPartition(0, 1) = %q, want %q", partition, want)
	}
}

func TestModelDiskBounds(t *testing.T) {
	for index, want := range map[int]string{
		0:                 "0000:00:07.0",
		MaxModelDisks - 1: "0000:00:1e.0",
	} {
		got, err := modelDiskPCIAddress(index)
		if err != nil {
			t.Fatalf("modelDiskPCIAddress(%d): %v", index, err)
		}
		if got != want {
			t.Fatalf("modelDiskPCIAddress(%d) = %q, want %q", index, got, want)
		}
	}
	for _, index := range []int{-1, lastUsableDiskPCISlot - firstModelDiskPCISlot + 1} {
		if _, err := modelDiskPCIAddress(index); err == nil {
			t.Fatalf("modelDiskPCIAddress(%d) succeeded", index)
		}
	}
}

func addPCIDisk(t *testing.T, fixture deviceFixture, controller, name string) {
	t.Helper()
	blockDir := filepath.Join(
		fixture.pci, controller,
		"virtio0", "block", name,
	)
	mustMkdir(t, blockDir)
	mustWrite(t, filepath.Join(fixture.pci, controller, "vendor"), virtioPCIVendorID+"\n")
	mustWrite(t, filepath.Join(fixture.pci, controller, "device"), virtioBlkPCIDeviceID+"\n")
	mustMkdir(t, filepath.Join(fixture.sys, name, "device"))
	serial := rootDiskSerial
	switch controller {
	case configDiskPCIAddress:
		serial = configDiskSerial
	case externalDiskPCIAddress:
		serial = externalDiskSerial
	default:
		if controller != rootDiskPCIAddress {
			slot, _ := strconv.ParseInt(strings.TrimSuffix(strings.TrimPrefix(controller, "0000:00:"), ".0"), 16, 32)
			serial = modelDiskSerial(int(slot) - firstModelDiskPCISlot)
		}
	}
	mustWrite(t, filepath.Join(fixture.sys, name, "serial"), serial+"\n")
	mustWrite(t, filepath.Join(fixture.dev, name), "")
}

func addPartition(t *testing.T, fixture deviceFixture, disk, name string, number int) {
	t.Helper()
	partitionDir := filepath.Join(fixture.sys, disk, name)
	mustMkdir(t, partitionDir)
	mustWrite(t, filepath.Join(partitionDir, "partition"), strconv.Itoa(number)+"\n")
	mustWrite(t, filepath.Join(fixture.dev, name), "")
}

func mustMkdir(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0755); err != nil {
		t.Fatal(err)
	}
}

func mustWrite(t *testing.T, path, data string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(data), 0644); err != nil {
		t.Fatal(err)
	}
}
