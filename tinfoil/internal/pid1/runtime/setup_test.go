package runtime

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestEnsureSymlinkCreatesAndReplacesStaleLink(t *testing.T) {
	linkPath := filepath.Join(t.TempDir(), "run", "shm")

	if err := ensureSymlink("/dev/shm", linkPath); err != nil {
		t.Fatalf("ensureSymlink create: %v", err)
	}
	if got, err := os.Readlink(linkPath); err != nil || got != "/dev/shm" {
		t.Fatalf("symlink target = %q, %v; want /dev/shm", got, err)
	}
	if err := ensureSymlink("/dev/shm", linkPath); err != nil {
		t.Fatalf("ensureSymlink idempotent: %v", err)
	}
	if err := os.Remove(linkPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/stale", linkPath); err != nil {
		t.Fatal(err)
	}
	if err := ensureSymlink("/dev/shm", linkPath); err != nil {
		t.Fatalf("ensureSymlink replace stale: %v", err)
	}
	if got, err := os.Readlink(linkPath); err != nil || got != "/dev/shm" {
		t.Fatalf("symlink target after replace = %q, %v; want /dev/shm", got, err)
	}
}

func TestRamdiskSizeGB(t *testing.T) {
	tests := []struct {
		name     string
		memGB    uint64
		wantSize uint64
		wantFB   bool
	}{
		{name: "large", memGB: 128, wantSize: 112},
		{name: "minimum-full", memGB: 32, wantSize: 16},
		{name: "below-minimum", memGB: 31, wantSize: 4, wantFB: true},
		{name: "development", memGB: 16, wantSize: 4, wantFB: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotSize, gotFallback, err := ramdiskSizeGB(tt.memGB * 1024 * 1024)
			if err != nil {
				t.Fatalf("ramdiskSizeGB: %v", err)
			}
			if gotSize != tt.wantSize || gotFallback != tt.wantFB {
				t.Fatalf("size,fallback = %d,%t; want %d,%t", gotSize, gotFallback, tt.wantSize, tt.wantFB)
			}
		})
	}
	if _, _, err := ramdiskSizeGB(0); err == nil {
		t.Fatal("ramdiskSizeGB(0) succeeded")
	}
}

func TestMemoryKBUsesKernelUnit(t *testing.T) {
	got, err := memoryKB(64*1024*1024, 1024)
	if err != nil || got != 64*1024*1024 {
		t.Fatalf("memoryKB = %d, %v; want %d", got, err, uint64(64*1024*1024))
	}
	if got, err := memoryKB(1024, 0); err != nil || got != 1 {
		t.Fatalf("memoryKB unit zero = %d, %v; want 1", got, err)
	}
	if _, err := memoryKB(0, 1); err == nil {
		t.Fatal("memoryKB accepted zero RAM")
	}
	if _, err := memoryKB(^uint64(0), 2); err == nil {
		t.Fatal("memoryKB accepted overflowing RAM")
	}
}

func TestIsMountPointUsesKernelMountIDs(t *testing.T) {
	mounted, err := isMountPoint("/proc")
	if err != nil {
		t.Fatalf("isMountPoint(/proc): %v", err)
	}
	if !mounted {
		t.Fatal("/proc is not detected as a mount point")
	}
	mounted, err = isMountPoint(t.TempDir())
	if err != nil {
		t.Fatalf("isMountPoint(temp): %v", err)
	}
	if mounted {
		t.Fatal("ordinary temporary directory detected as a mount point")
	}
}

func TestIsMountPointFailsClosedWithoutKernelMountID(t *testing.T) {
	noMountID := func(_ int, _ string, _, _ int, info *unix.Statx_t) error {
		info.Mask = 0
		return nil
	}
	if _, err := isMountPointWith("/target", noMountID); err == nil {
		t.Fatal("isMountPointWith accepted missing STATX_MNT_ID")
	}

	statErr := errors.New("statx unavailable")
	failing := func(_ int, _ string, _, _ int, _ *unix.Statx_t) error {
		return statErr
	}
	if _, err := isMountPointWith("/target", failing); !errors.Is(err, statErr) {
		t.Fatalf("isMountPointWith error = %v, want %v", err, statErr)
	}
}

func TestApplySysctls(t *testing.T) {
	root := t.TempDir()
	procRoot := filepath.Join(root, "proc", "sys")
	kptrPath := filepath.Join(procRoot, "kernel", "kptr_restrict")
	mmapPath := filepath.Join(procRoot, "vm", "mmap_min_addr")
	for _, path := range []string{kptrPath, mmapPath} {
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, nil, 0644); err != nil {
			t.Fatal(err)
		}
	}
	policy := []sysctlSetting{
		{path: "kernel/kptr_restrict", value: "1"},
		{path: "net/core/default_qdisc", value: "fq_codel", optional: true},
		{path: "vm/mmap_min_addr", value: "65536"},
	}

	var logs []string
	err := applySysctls(procRoot, policy, func(format string, args ...any) {
		logs = append(logs, format)
	})
	if err != nil {
		t.Fatalf("applySysctls: %v", err)
	}
	if got, err := os.ReadFile(kptrPath); err != nil || string(got) != "1\n" {
		t.Fatalf("kptr_restrict = %q, %v; want 1", got, err)
	}
	if got, err := os.ReadFile(mmapPath); err != nil || string(got) != "65536\n" {
		t.Fatalf("mmap_min_addr = %q, %v; want 65536", got, err)
	}
	if len(logs) != 2 {
		t.Fatalf("log count = %d, want optional skip and completion", len(logs))
	}
}

func TestApplySysctlsFailsClosed(t *testing.T) {
	if err := applySysctls(
		filepath.Join(t.TempDir(), "missing-proc"),
		[]sysctlSetting{{path: "kernel/kptr_restrict", value: "1"}},
		nil,
	); err == nil {
		t.Fatal("applySysctls accepted missing required key")
	}
}
