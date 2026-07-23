package runtime

import (
	"os"
	"path/filepath"
	"testing"
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
	if !isMountPoint("/proc") {
		t.Fatal("/proc is not detected as a mount point")
	}
	if isMountPoint(t.TempDir()) {
		t.Fatal("ordinary temporary directory detected as a mount point")
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

func TestApplySysctlsVerifiesKernelState(t *testing.T) {
	procRoot := t.TempDir()
	path := filepath.Join(procRoot, "kernel", "kptr_restrict")
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/dev/null", path); err != nil {
		t.Fatal(err)
	}

	err := applySysctls(
		procRoot,
		[]sysctlSetting{{path: "kernel/kptr_restrict", value: "1"}},
		nil,
	)
	if err == nil {
		t.Fatal("applySysctls accepted a value that did not persist")
	}
}

func TestSysctlPolicyHardensPinnedKernelInterfaces(t *testing.T) {
	want := map[string]string{
		"kernel/oops_limit":                "1",
		"kernel/panic_on_oops":             "1",
		"kernel/panic_on_warn":             "0",
		"kernel/perf_event_paranoid":       "4",
		"kernel/unprivileged_bpf_disabled": "1",
		"kernel/unprivileged_userns_clone": "0",
		"kernel/warn_limit":                "10",
		"net/core/bpf_jit_harden":          "2",
		"net/ipv4/ip_forward":              "1",
	}

	for _, setting := range sysctlPolicy {
		if setting.path == "kernel/sysrq" {
			t.Error("runtime sysrq policy present even though CONFIG_MAGIC_SYSRQ is disabled")
		}
		if value, ok := want[setting.path]; ok {
			if setting.value != value {
				t.Errorf("sysctl %s = %q, want %q", setting.path, setting.value, value)
			}
			if setting.optional {
				t.Errorf("security sysctl %s is optional", setting.path)
			}
			delete(want, setting.path)
		}
	}
	for path := range want {
		t.Errorf("security sysctl %s is missing", path)
	}
}
