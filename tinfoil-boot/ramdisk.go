package main

import (
	"fmt"
	"log/slog"
	"os"

	"golang.org/x/sys/unix"
)

const (
	ramdiskPath  = "/mnt/ramdisk"
	tmpPath      = "/tmp"
	minRamdiskGB = 4
	reservedGB   = 16
	tmpSizeMB    = 512
)

// setupRamdisk creates and mounts the ramdisk filesystems
func setupRamdisk() error {
	// Calculate ramdisk size based on available RAM
	totalRAM, err := getTotalRAMGB()
	if err != nil {
		return fmt.Errorf("getting total RAM: %w", err)
	}

	size := totalRAM - reservedGB
	if size < minRamdiskGB {
		slog.Warn("not enough RAM, using fallback size",
			"total_gb", totalRAM,
			"fallback_gb", minRamdiskGB)
		size = minRamdiskGB
	} else {
		slog.Info("allocating ramdisk",
			"size_gb", size,
			"total_ram_gb", totalRAM)
	}

	// Ensure mount point exists
	if err := os.MkdirAll(ramdiskPath, 0755); err != nil {
		return fmt.Errorf("creating ramdisk mount point: %w", err)
	}

	// Mount main ramdisk with world-writable permissions
	opts := fmt.Sprintf("size=%dG,mode=0777", size)
	if err := unix.Mount("tmpfs", ramdiskPath, "tmpfs", 0, opts); err != nil {
		return fmt.Errorf("mounting ramdisk: %w", err)
	}

	// Mount /tmp as smaller tmpfs
	tmpOpts := fmt.Sprintf("size=%dM", tmpSizeMB)
	if err := unix.Mount("tmpfs", tmpPath, "tmpfs", 0, tmpOpts); err != nil {
		return fmt.Errorf("mounting /tmp: %w", err)
	}

	slog.Info("ramdisk mounted", "path", ramdiskPath, "size_gb", size)
	return nil
}

func getTotalRAMGB() (int, error) {
	var info unix.Sysinfo_t
	if err := unix.Sysinfo(&info); err != nil {
		return 0, err
	}

	// Totalram is in units of info.Unit bytes
	totalBytes := uint64(info.Totalram) * uint64(info.Unit)
	return int(totalBytes / (1024 * 1024 * 1024)), nil
}
