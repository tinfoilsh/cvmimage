package device

import (
	"os"
	"path/filepath"
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
		"virtio0", "host0", "target0:0:0", "0:0:0:0", "block", name,
	)
	mustMkdir(t, blockDir)
	mustMkdir(t, filepath.Join(fixture.sys, name))
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
