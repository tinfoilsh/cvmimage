package metrics

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseCPUUtilization(t *testing.T) {
	got, err := parseCPUUtilization("cpu  100 20 30 50 7 8 9 10 11 12\ncpu0 1 2 3 4\n")
	if err != nil {
		t.Fatal(err)
	}
	if got != 75 {
		t.Fatalf("parseCPUUtilization() = %d, want 75", got)
	}
}

func TestParseCPUUtilizationRejectsInvalidInput(t *testing.T) {
	for _, input := range []string{
		"cpu 1 2 3\n",
		"cpu 1 invalid 3 4\n",
		"cpu 0 0 0 0\n",
	} {
		if _, err := parseCPUUtilization(input); err == nil {
			t.Fatalf("parseCPUUtilization(%q) succeeded", input)
		}
	}
}

func TestParseCPUUtilizationRejectsOverflow(t *testing.T) {
	for _, input := range []string{
		fmt.Sprintf("cpu %d 1 0 1\n", uint64(math.MaxUint64)),
		fmt.Sprintf("cpu %d 0 0 1\n", uint64(math.MaxUint64)),
	} {
		if _, err := parseCPUUtilization(input); err == nil || !strings.Contains(err.Error(), "overflow") {
			t.Fatalf("parseCPUUtilization(%q) error = %v, want overflow", input, err)
		}
	}
}

func TestParseMemoryUsageUsesMemAvailable(t *testing.T) {
	total, used, err := parseMemoryUsage("MemTotal: 1048576 kB\nMemFree: 1 kB\nMemAvailable: 262144 kB\nBuffers: 2 kB\nCached: 3 kB\n")
	if err != nil {
		t.Fatal(err)
	}
	if total != 1<<30 || used != 3<<28 {
		t.Fatalf("parseMemoryUsage() = (%d, %d), want (%d, %d)", total, used, uint64(1<<30), uint64(3<<28))
	}
}

func TestParseMemoryUsageFallsBackToLegacyFields(t *testing.T) {
	total, used, err := parseMemoryUsage("MemTotal: 1024 kB\nMemFree: 100 kB\nBuffers: 20 kB\nCached: 300 kB\n")
	if err != nil {
		t.Fatal(err)
	}
	if total != 1024*1024 || used != 604*1024 {
		t.Fatalf("parseMemoryUsage() = (%d, %d), want (%d, %d)", total, used, 1024*1024, 604*1024)
	}
}

func TestParseMemoryUsageRejectsInvalidInput(t *testing.T) {
	for _, input := range []string{
		"MemAvailable: 1 kB\n",
		"MemTotal: invalid kB\nMemAvailable: 1 kB\n",
		"MemTotal: 1 MB\nMemAvailable: 1 kB\n",
		"MemTotal: 1 kB\nMemAvailable: 2 kB\n",
		"MemTotal: 10 kB\nMemFree: 1 kB\n",
	} {
		if _, _, err := parseMemoryUsage(input); err == nil {
			t.Fatalf("parseMemoryUsage(%q) succeeded", input)
		}
	}
}

func TestParseMemoryUsageRejectsKilobyteOverflow(t *testing.T) {
	overflowKilobytes := uint64(math.MaxUint64/bytesPerProcKilobyte + 1)
	input := fmt.Sprintf("MemTotal: %d kB\nMemAvailable: 1 kB\n", overflowKilobytes)
	if _, _, err := parseMemoryUsage(input); err == nil || !strings.Contains(err.Error(), "overflow") {
		t.Fatalf("parseMemoryUsage() error = %v, want overflow", err)
	}
}

func TestParseMemoryUsageRejectsAggregateOverflow(t *testing.T) {
	maxBytesKilobytes := uint64(math.MaxUint64 / bytesPerProcKilobyte)
	input := fmt.Sprintf("MemTotal: %d kB\nMemFree: %d kB\nBuffers: 1 kB\nCached: 0 kB\n", maxBytesKilobytes, maxBytesKilobytes)
	if _, _, err := parseMemoryUsage(input); err == nil || !strings.Contains(err.Error(), "overflow") {
		t.Fatalf("parseMemoryUsage() error = %v, want overflow", err)
	}
}

func TestReadCPUUtilizationRejectsOversizedProcStat(t *testing.T) {
	path := writeTestProcFile(t, procStatMaxBytes+1)
	if _, err := readCPUUtilizationFile(path); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("readCPUUtilizationFile() error = %v, want size limit rejection", err)
	}
}

func TestReadMemoryUsageRejectsOversizedProcMeminfo(t *testing.T) {
	path := writeTestProcFile(t, procMeminfoMaxBytes+1)
	if _, _, err := readMemoryUsageFile(path); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("readMemoryUsageFile() error = %v, want size limit rejection", err)
	}
}

func writeTestProcFile(t *testing.T, size int) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "proc")
	if err := os.WriteFile(path, []byte(strings.Repeat("x", size)), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
