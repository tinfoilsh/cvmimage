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
	configDiskPCIAddress   = "0000:00:05.0"
	externalDiskPCIAddress = "0000:00:06.0"
	firstModelDiskPCISlot  = 7
	lastUsableDiskPCISlot  = 30 // Q35 reserves slot 31 for ISA/SATA/SMBus.

	EMWPPayloadPartition = 1
	// MaxModelDisks is the number of Q35 slots reserved for model disks.
	MaxModelDisks = lastUsableDiskPCISlot - firstModelDiskPCISlot + 1
)

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
		return findDiskByPCIAddress(configDiskPCIAddress)
	})
}

// ExternalConfigDisk returns the disk below the fixed external-config
// controller.
func ExternalConfigDisk() (string, error) {
	return waitForDevice(func() (string, error) {
		return findDiskByPCIAddress(externalDiskPCIAddress)
	})
}

// ModelDisk returns the disk at a model's fixed position in the config.
func ModelDisk(index int) (string, error) {
	pciAddress, err := modelDiskPCIAddress(index)
	if err != nil {
		return "", err
	}
	return waitForDevice(func() (string, error) {
		return findDiskByPCIAddress(pciAddress)
	})
}

// ModelPartition returns a numbered partition on a model's fixed disk.
func ModelPartition(index, partition int) (string, error) {
	pciAddress, err := modelDiskPCIAddress(index)
	if err != nil {
		return "", err
	}
	return waitForDevice(func() (string, error) {
		disk, err := findDiskByPCIAddress(pciAddress)
		if err != nil {
			return "", err
		}
		return findPartition(disk, partition)
	})
}

func modelDiskPCIAddress(index int) (string, error) {
	slot := firstModelDiskPCISlot + index
	if index < 0 || slot > lastUsableDiskPCISlot {
		return "", fmt.Errorf("model index %d exceeds the measured PCI slot range", index)
	}
	return fmt.Sprintf("0000:00:%02x.0", slot), nil
}

func waitForDevice(find func() (string, error)) (string, error) {
	deadline := time.Now().Add(deviceWaitTimeout)
	var lastErr error
	for {
		path, err := find()
		if err == nil {
			return path, nil
		}
		lastErr = err
		if time.Now().After(deadline) {
			return "", lastErr
		}
		time.Sleep(deviceWaitDelay)
	}
}

// findDiskByPCIAddress follows kernel topology only. It deliberately does not
// parse serial/VPD bytes or disk contents as identity.
func findDiskByPCIAddress(pciAddress string) (string, error) {
	pattern := filepath.Join(
		sysBusPCIDevices, pciAddress,
		"virtio*", "host*", "target*", "*", "block", "*",
	)
	blockPaths, err := filepath.Glob(pattern)
	if err != nil {
		return "", fmt.Errorf("finding disk below PCI device %s: %w", pciAddress, err)
	}
	var matches []string
	for _, blockPath := range blockPaths {
		path := filepath.Join(devDir, filepath.Base(blockPath))
		if _, err := os.Stat(path); err == nil {
			matches = append(matches, path)
		}
	}
	sort.Strings(matches)
	matches = compactPaths(matches)
	if len(matches) == 1 {
		return matches[0], nil
	}
	return "", fmt.Errorf(
		"expected one disk below PCI device %s, found %d",
		pciAddress, len(matches),
	)
}

func compactPaths(paths []string) []string {
	if len(paths) < 2 {
		return paths
	}
	out := paths[:1]
	for _, path := range paths[1:] {
		if path != out[len(out)-1] {
			out = append(out, path)
		}
	}
	return out
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
