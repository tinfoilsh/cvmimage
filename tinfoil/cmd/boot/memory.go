package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const memmapRoot = "/sys/firmware/memmap"

// Windows that get an E820 entry without being RAM the host provided, so the
// total discounts whatever an entry holds in them:
//
//   - the shim's reset page, the last page of the address space rather than of
//     the guest's RAM; firmware/src/boot.rs leaves it out of min_memory too
//   - the HyperTransport hole QEMU reserves for any guest whose vCPU claims
//     AuthenticAMD, which falls below the top of RAM once the guest is large
//     enough that QEMU restacks its high bank above 1 TiB (hw/i386/pc.c)
var notGuestRAM = [][2]uint64{
	{0xffff_f000, 0x1_0000_0000},
	{1012 << 30, 1024 << 30},
}

// enforceRAMSize holds the launch to the memory the config asked for. The
// launch profile is fixed so that the measurement is, which leaves the size of
// the machine to the host; the config is what HOST_DATA commits to, so
// comparing the two here is what makes the host's choice binding. Without it a
// guest sold 64 GiB starts contentedly on 4.
//
// E820 is the right thing to count, and its total is the RAM exactly: the
// apertures a host describes are absent from it, everything else below the top
// of RAM has an entry whatever its type, and every page it calls memory was
// PVALIDATEd before Linux ran. A host that claims RAM it has not backed fails
// the accept walk rather than reaching this check.
func enforceRAMSize(root string, requestedMiB int) (string, error) {
	if requestedMiB < 1 {
		return "", fmt.Errorf("config requests %d MiB of RAM, at least 1 is required", requestedMiB)
	}
	given, err := firmwareMemoryBytes(root)
	if err != nil {
		return "", err
	}
	requested := uint64(requestedMiB) << 20
	if given != requested {
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
		// Subtracting the overlap rather than skipping the entry: an entry may
		// hold one of these windows exactly, as the reset page does on TDX, but
		// nothing stops it being coalesced with a neighbour of the same type.
		length := end - start + 1
		for _, window := range notGuestRAM {
			length -= overlap(start, end+1, window[0], window[1])
		}
		total += length
	}
	if counted == 0 {
		return 0, fmt.Errorf("firmware memory map is empty")
	}
	return total, nil
}

// overlap is the length the half-open [aLow, aHigh) and [bLow, bHigh) share.
func overlap(aLow, aHigh, bLow, bHigh uint64) uint64 {
	low, high := max(aLow, bLow), min(aHigh, bHigh)
	if low >= high {
		return 0
	}
	return high - low
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
