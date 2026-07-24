package metrics

import (
	"fmt"
	"io"
	"math"
	"os"
	"strconv"
	"strings"
)

const (
	procStatPath         = "/proc/stat"
	procMeminfoPath      = "/proc/meminfo"
	procStatMaxBytes     = 1 << 20
	procMeminfoMaxBytes  = 64 << 10
	bytesPerProcKilobyte = 1024
)

func readCPUUtilization() (int, error) {
	return readCPUUtilizationFile(procStatPath)
}

func readCPUUtilizationFile(path string) (int, error) {
	data, err := readBoundedFile(path, procStatMaxBytes)
	if err != nil {
		return 0, err
	}
	return parseCPUUtilization(string(data))
}

func parseCPUUtilization(data string) (int, error) {
	line, _, _ := strings.Cut(data, "\n")
	fields := strings.Fields(line)
	if len(fields) < 5 || fields[0] != "cpu" {
		return 0, fmt.Errorf("invalid %s aggregate CPU line", procStatPath)
	}

	var times [4]uint64
	for i := range times {
		value, err := strconv.ParseUint(fields[i+1], 10, 64)
		if err != nil {
			return 0, fmt.Errorf("invalid %s aggregate CPU value: %w", procStatPath, err)
		}
		times[i] = value
	}

	busy, ok := addUint64(times[0], times[1])
	if !ok {
		return 0, fmt.Errorf("invalid %s aggregate CPU time overflow", procStatPath)
	}
	busy, ok = addUint64(busy, times[2])
	if !ok {
		return 0, fmt.Errorf("invalid %s aggregate CPU time overflow", procStatPath)
	}
	total, ok := addUint64(busy, times[3])
	if !ok {
		return 0, fmt.Errorf("invalid %s aggregate CPU time overflow", procStatPath)
	}
	if total == 0 {
		return 0, fmt.Errorf("invalid %s zero aggregate CPU time", procStatPath)
	}
	return int(float64(busy) / float64(total) * 100), nil
}

func readMemoryUsage() (uint64, uint64, error) {
	return readMemoryUsageFile(procMeminfoPath)
}

func readMemoryUsageFile(path string) (uint64, uint64, error) {
	data, err := readBoundedFile(path, procMeminfoMaxBytes)
	if err != nil {
		return 0, 0, err
	}
	return parseMemoryUsage(string(data))
}

func parseMemoryUsage(data string) (uint64, uint64, error) {
	var total, free, available, buffers, cached uint64
	var haveTotal, haveFree, haveAvailable, haveBuffers, haveCached bool

	for line := range strings.SplitSeq(data, "\n") {
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		var destination *uint64
		var present *bool
		switch name {
		case "MemTotal":
			destination, present = &total, &haveTotal
		case "MemFree":
			destination, present = &free, &haveFree
		case "MemAvailable":
			destination, present = &available, &haveAvailable
		case "Buffers":
			destination, present = &buffers, &haveBuffers
		case "Cached":
			destination, present = &cached, &haveCached
		default:
			continue
		}

		fields := strings.Fields(value)
		if len(fields) != 2 || fields[1] != "kB" {
			return 0, 0, fmt.Errorf("invalid %s %s value", procMeminfoPath, name)
		}
		kilobytes, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			return 0, 0, fmt.Errorf("invalid %s %s value: %w", procMeminfoPath, name, err)
		}
		if kilobytes > math.MaxUint64/bytesPerProcKilobyte {
			return 0, 0, fmt.Errorf("invalid %s %s value overflow", procMeminfoPath, name)
		}
		*destination = kilobytes * bytesPerProcKilobyte
		*present = true
	}

	if !haveTotal {
		return 0, 0, fmt.Errorf("missing %s MemTotal", procMeminfoPath)
	}
	usedBase := available
	if !haveAvailable {
		if !haveFree || !haveBuffers || !haveCached {
			return 0, 0, fmt.Errorf("missing %s memory availability fields", procMeminfoPath)
		}
		var ok bool
		usedBase, ok = addUint64(free, buffers)
		if !ok {
			return 0, 0, fmt.Errorf("invalid %s available memory overflow", procMeminfoPath)
		}
		usedBase, ok = addUint64(usedBase, cached)
		if !ok {
			return 0, 0, fmt.Errorf("invalid %s available memory overflow", procMeminfoPath)
		}
	}
	if usedBase > total {
		return 0, 0, fmt.Errorf("invalid %s available memory exceeds total", procMeminfoPath)
	}
	return total, total - usedBase, nil
}

func readBoundedFile(path string, maxBytes int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("%s exceeds %d-byte limit", path, maxBytes)
	}
	return data, nil
}

func addUint64(left, right uint64) (uint64, bool) {
	if right > math.MaxUint64-left {
		return 0, false
	}
	return left + right, true
}
