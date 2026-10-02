package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const memmapRoot = "/sys/firmware/memmap"

// enforceRAMSize holds the launch to the memory the config asked for. The
// launch profile is fixed so that the measurement is, which leaves the size of
// the machine to the host; the config is what HOST_DATA commits to, so
// comparing the two here is what makes the host's choice binding. Without it a
// guest sold 64 GiB starts contentedly on 4.
//
// The total is a floor, not an equality. Every page E820 calls memory was
// PVALIDATEd before Linux ran, so a host that claims RAM it has not backed
// fails the accept walk rather than reaching this check; what E820 cannot do
// is report the host's RAM exactly, because this image places a handful of
// pages in windows the host does not call memory and each one still earns an
// entry. Measured on an eight and a sixteen GiB guest that is four pages, and
// on a two GiB guest none, since QEMU only splits the bank around the 32-bit
// aperture once the guest outgrows it. Demanding equality made the slack a
// boot failure for every guest larger than four GiB; a shortfall is the thing
// worth refusing, and it is orders of magnitude, not pages.
func enforceRAMSize(root string, requestedMiB int) (string, error) {
	if requestedMiB < 1 {
		return "", fmt.Errorf("config requests %d MiB of RAM, at least 1 is required", requestedMiB)
	}
	given, err := firmwareMemoryBytes(root)
	if err != nil {
		return "", err
	}
	requested := uint64(requestedMiB) << 20
	if given < requested {
		return "", fmt.Errorf("config requests %d MiB of RAM, the launch provides %d bytes",
			requestedMiB, given)
	}
	return fmt.Sprintf("%d MiB of RAM", requestedMiB), nil
}

// firmwareMemoryBytes totals the E820 entries sysfs reports, whose ends are
// inclusive.
func firmwareMemoryBytes(root string) (uint64, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return 0, fmt.Errorf("reading firmware memory map: %w", err)
	}
	var total uint64
	var counted int
	for _, entry := range entries {
		dir := filepath.Join(root, entry.Name())
		start, err := memmapValue(dir, "start")
		if err != nil {
			return 0, err
		}
		end, err := memmapValue(dir, "end")
		if err != nil {
			return 0, err
		}
		if end < start {
			return 0, fmt.Errorf("firmware memory map entry %s ends before it starts", entry.Name())
		}
		counted++
		total += end - start + 1
	}
	if counted == 0 {
		return 0, fmt.Errorf("firmware memory map is empty")
	}
	return total, nil
}

func memmapValue(dir, name string) (uint64, error) {
	data, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return 0, fmt.Errorf("reading firmware memory map: %w", err)
	}
	text := strings.TrimSpace(string(data))
	value, err := strconv.ParseUint(strings.TrimPrefix(text, "0x"), 16, 64)
	if err != nil {
		return 0, fmt.Errorf("unparsable firmware memory map %s %q", name, text)
	}
	return value, nil
}
