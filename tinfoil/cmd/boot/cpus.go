package main

import (
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
)

const cpuRoot = "/sys/devices/system/cpu"

// enforceCPUCount offlines the processors the config did not ask for. The
// launch profile is fixed so that the measurement is; the count the workload
// actually gets travels in the config and is applied here.
func enforceCPUCount(root string, requested int) (string, error) {
	if requested < 1 {
		return "", fmt.Errorf("config requests %d CPUs, at least 1 is required", requested)
	}
	present, err := presentCPUs(root)
	if err != nil {
		return "", err
	}
	if requested > len(present) {
		return "", fmt.Errorf("config requests %d CPUs, the launch profile provides %d", requested, len(present))
	}
	// present[0] is CPU 0, which Linux cannot offline; requested >= 1 keeps it.
	for _, id := range present[requested:] {
		path := fmt.Sprintf("%s/cpu%d/online", root, id)
		if err := os.WriteFile(path, []byte("0\n"), 0o644); err != nil {
			return "", fmt.Errorf("offlining cpu%d: %w", id, err)
		}
	}
	// The present list is shaped by the host, so counting it proves nothing
	// about what came up: the kernel states separately which processors are
	// running, and the config is met only if those are exactly the ones kept.
	online, err := cpuList(root, "online")
	if err != nil {
		return "", err
	}
	if !slices.Equal(online, present[:requested]) {
		return "", fmt.Errorf("config requests %d CPUs, %v are online", requested, online)
	}
	return fmt.Sprintf("%d of %d CPUs online", requested, len(present)), nil
}

func presentCPUs(root string) ([]int, error) {
	return cpuList(root, "present")
}

// cpuList parses a sysfs CPU list ("0-7", "0,2-3") in ascending order.
func cpuList(root, name string) ([]int, error) {
	data, err := os.ReadFile(root + "/" + name)
	if err != nil {
		return nil, fmt.Errorf("reading %s CPUs: %w", name, err)
	}
	var ids []int
	for _, span := range strings.Split(strings.TrimSpace(string(data)), ",") {
		low, high, found := strings.Cut(span, "-")
		if !found {
			high = low
		}
		first, err := strconv.Atoi(low)
		if err != nil {
			return nil, fmt.Errorf("unparsable CPU list %q", data)
		}
		last, err := strconv.Atoi(high)
		if err != nil || last < first {
			return nil, fmt.Errorf("unparsable CPU list %q", data)
		}
		for id := first; id <= last; id++ {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("no CPUs are %s", name)
	}
	return ids, nil
}
