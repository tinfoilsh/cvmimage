package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const memmapRoot = "/sys/firmware/memmap"

// imageReservedBytes bounds the RAM the image's own reserved pages take out of
// the bank: those below 2 MiB and the TDX reset page, as compiler/src/image.rs
// checks.
const imageReservedBytes = 2 << 20

// enforceRAMSize holds the launch to at least the memory the config asked for,
// which HOST_DATA commits to while the host picks the machine's size. Only
// System RAM counts: the loader or the shim validated every page of it, but
// nothing the host marks reserved.
func enforceRAMSize(root string, requestedMiB int) (string, error) {
	if requestedMiB < 1 {
		return "", fmt.Errorf("config requests %d MiB of RAM, at least 1 is required", requestedMiB)
	}
	given, err := systemRAMBytes(root)
	if err != nil {
		return "", err
	}
	if uint64(requestedMiB) > (given+imageReservedBytes)>>20 {
		return "", fmt.Errorf("config requests %d MiB of RAM, the launch provides %d bytes",
			requestedMiB, given)
	}
	return fmt.Sprintf("%d MiB of RAM", requestedMiB), nil
}

// systemRAMBytes totals the System RAM entries sysfs reports, whose ends are
// inclusive.
func systemRAMBytes(root string) (uint64, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return 0, fmt.Errorf("reading firmware memory map: %w", err)
	}
	if len(entries) == 0 {
		return 0, fmt.Errorf("firmware memory map is empty")
	}
	var total uint64
	for _, entry := range entries {
		dir := filepath.Join(root, entry.Name())
		kind, err := os.ReadFile(filepath.Join(dir, "type"))
		if err != nil {
			return 0, fmt.Errorf("reading firmware memory map: %w", err)
		}
		if strings.TrimSpace(string(kind)) != "System RAM" {
			continue
		}
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
		total += end - start + 1
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
