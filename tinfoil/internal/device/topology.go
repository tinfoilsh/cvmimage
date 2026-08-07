package device

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	// These are the measured PCI addresses QEMU assigned before tinfoild made
	// them explicit. They MUST match tinfoild/admin/guest_topology.go.
	rootDiskPCIAddress     = "0000:00:04.0"
	configDiskPCIAddress   = "0000:00:05.0"
	externalDiskPCIAddress = "0000:00:06.0"
	firstModelDiskPCISlot  = 7
	lastUsableDiskPCISlot  = 30 // Q35 reserves slot 31 for ISA/SATA/SMBus.
	virtioPCIVendorID      = "0x1af4"
	virtioBlkPCIDeviceID   = "0x1042"
	// Disk serials are part of the fixed launcher/guest contract.
	rootDiskSerial     = "tinfoil-rootdisk"
	configDiskSerial   = "tinfoil-config"
	externalDiskSerial = "tinfoil-ext-config"

	rootDataPartition    = 1
	rootVerityPartition  = 2
	EMWPPayloadPartition = 1
	// MaxModelDisks is the number of Q35 slots reserved for model disks.
	MaxModelDisks = lastUsableDiskPCISlot - firstModelDiskPCISlot + 1
)

// RootPartitions returns the fixed data and verity partitions below the
// measured root controller.
func RootPartitions() (string, string, error) {
	partitions, err := waitForDevice(func() ([2]string, error) {
		disk, err := findDiskByPCIAddress(rootDiskPCIAddress, rootDiskSerial)
		if err != nil {
			return [2]string{}, err
		}
		root, verity, err := findRootPartitions(disk)
		return [2]string{root, verity}, err
	})
	if err != nil {
		return "", "", err
	}
	return partitions[0], partitions[1], nil
}

var (
	sysBusPCIDevices = "/sys/bus/pci/devices"
	sysBlockDir      = "/sys/block"
	devDir           = "/dev"

	deviceWaitTimeout = 30 * time.Second
	deviceWaitDelay   = 100 * time.Millisecond
)

// ConfigDisk returns the disk below the fixed config controller.
func ConfigDisk() (string, error) {
	return waitForDevice(func() (string, error) {
		return findDiskByPCIAddress(configDiskPCIAddress, configDiskSerial)
	})
}

// ExternalConfigDisk returns the disk below the fixed external-config
// controller.
func ExternalConfigDisk() (string, error) {
	return waitForDevice(func() (string, error) {
		return findDiskByPCIAddress(externalDiskPCIAddress, externalDiskSerial)
	})
}

// ModelDisk returns the disk at a model's fixed position in the config.
func ModelDisk(index int) (string, error) {
	pciAddress, err := modelDiskPCIAddress(index)
	if err != nil {
		return "", err
	}
	return waitForDevice(func() (string, error) {
		return findDiskByPCIAddress(pciAddress, modelDiskSerial(index))
	})
}

// ModelPartition returns a numbered partition on a model's fixed disk.
func ModelPartition(index, partition int) (string, error) {
	pciAddress, err := modelDiskPCIAddress(index)
	if err != nil {
		return "", err
	}
	return waitForDevice(func() (string, error) {
		disk, err := findDiskByPCIAddress(pciAddress, modelDiskSerial(index))
		if err != nil {
			return "", err
		}
		return findPartition(disk, partition)
	})
}

func modelDiskSerial(index int) string {
	return fmt.Sprintf("tinfoil-modelwrap%d", index+1)
}

func modelDiskPCIAddress(index int) (string, error) {
	slot := firstModelDiskPCISlot + index
	if index < 0 || slot > lastUsableDiskPCISlot {
		return "", fmt.Errorf("model index %d exceeds the measured PCI slot range", index)
	}
	return fmt.Sprintf("0000:00:%02x.0", slot), nil
}

func waitForDevice[T any](find func() (T, error)) (T, error) {
	deadline := time.Now().Add(deviceWaitTimeout)
	var lastErr error
	for {
		device, err := find()
		if err == nil {
			return device, nil
		}
		lastErr = err
		if time.Now().After(deadline) {
			var zero T
			return zero, lastErr
		}
		time.Sleep(deviceWaitDelay)
	}
}

// findDiskByPCIAddress accepts only the fixed modern virtio-blk PCI contract.
func findDiskByPCIAddress(pciAddress, expectedSerial string) (string, error) {
	pciPath := filepath.Join(sysBusPCIDevices, pciAddress)
	attributes := [...]struct {
		name     string
		expected string
	}{
		{name: "vendor", expected: virtioPCIVendorID},
		{name: "device", expected: virtioBlkPCIDeviceID},
	}
	for _, attribute := range attributes {
		value, err := os.ReadFile(filepath.Join(pciPath, attribute.name))
		if err != nil {
			return "", fmt.Errorf("reading %s for PCI device %s: %w", attribute.name, pciAddress, err)
		}
		if strings.TrimSpace(string(value)) != attribute.expected {
			return "", fmt.Errorf("PCI device %s has unexpected %s %q", pciAddress, attribute.name, strings.TrimSpace(string(value)))
		}
	}
	pattern := filepath.Join(
		pciPath, "virtio*", "block", "*",
	)
	blockPaths, err := filepath.Glob(pattern)
	if err != nil {
		return "", fmt.Errorf("finding disk below PCI device %s: %w", pciAddress, err)
	}
	sort.Strings(blockPaths)
	if len(blockPaths) != 1 {
		return "", fmt.Errorf(
			"expected one disk below PCI device %s, found %d",
			pciAddress, len(blockPaths),
		)
	}
	path := filepath.Join(devDir, filepath.Base(blockPaths[0]))
	serial, err := os.ReadFile(filepath.Join(sysBlockDir, filepath.Base(path), "serial"))
	if err != nil {
		return "", fmt.Errorf("reading serial for disk %s: %w", path, err)
	}
	if strings.TrimSpace(string(serial)) != expectedSerial {
		return "", fmt.Errorf("disk below PCI device %s has unexpected serial %q", pciAddress, strings.TrimSpace(string(serial)))
	}
	if _, err := os.Stat(path); err != nil {
		return "", fmt.Errorf("disk node %s not ready: %w", path, err)
	}
	return path, nil
}

func findRootPartitions(diskPath string) (string, string, error) {
	disk := filepath.Base(diskPath)
	partitionFiles, err := filepath.Glob(filepath.Join(sysBlockDir, disk, "*", "partition"))
	if err != nil {
		return "", "", fmt.Errorf("reading partitions for %s: %w", diskPath, err)
	}
	var root, verity string
	for _, partitionFile := range partitionFiles {
		name := filepath.Base(filepath.Dir(partitionFile))
		data, err := os.ReadFile(partitionFile)
		if err != nil {
			return "", "", fmt.Errorf("reading partition number for %s: %w", name, err)
		}
		number, err := strconv.Atoi(strings.TrimSpace(string(data)))
		if err != nil {
			return "", "", fmt.Errorf("invalid partition number for %s", name)
		}
		path := filepath.Join(devDir, name)
		if _, err := os.Stat(path); err != nil {
			return "", "", fmt.Errorf("partition node %s not ready: %w", path, err)
		}
		switch number {
		case rootDataPartition:
			if root != "" {
				return "", "", fmt.Errorf("duplicate root data partition on %s", diskPath)
			}
			root = path
		case rootVerityPartition:
			if verity != "" {
				return "", "", fmt.Errorf("duplicate root verity partition on %s", diskPath)
			}
			verity = path
		default:
			return "", "", fmt.Errorf("unexpected partition %d on %s", number, diskPath)
		}
	}
	if root == "" || verity == "" {
		return "", "", fmt.Errorf(
			"expected root partitions %d and %d on %s",
			rootDataPartition, rootVerityPartition, diskPath,
		)
	}
	return root, verity, nil
}

func findPartition(diskPath string, partition int) (string, error) {
	if partition <= 0 {
		return "", fmt.Errorf("invalid partition number %d", partition)
	}
	disk := filepath.Base(diskPath)
	entries, err := os.ReadDir(filepath.Join(sysBlockDir, disk))
	if err != nil {
		return "", fmt.Errorf("reading partitions for %s: %w", diskPath, err)
	}
	for _, entry := range entries {
		data, err := os.ReadFile(filepath.Join(sysBlockDir, disk, entry.Name(), "partition"))
		if err != nil {
			continue
		}
		found, err := strconv.Atoi(strings.TrimSpace(string(data)))
		if err != nil || found != partition {
			continue
		}
		path := filepath.Join(devDir, entry.Name())
		if _, err := os.Stat(path); err != nil {
			return "", fmt.Errorf("partition node %s not ready: %w", path, err)
		}
		return path, nil
	}
	return "", fmt.Errorf("partition %d on %s not found", partition, diskPath)
}
