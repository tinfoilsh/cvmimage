// Package runtime owns the filesystem and sysctl setup performed by PID 1.
package runtime

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"tinfoil/internal/boot"
)

const (
	// Ramdisk sizing preserves the legacy tinfoil-ramdisk policy: reserve
	// 16 GiB for the OS on production-sized hosts and use a small fixed
	// ramdisk on development hosts.
	ramdiskMinRAMGB   = 32
	ramdiskReserveGB  = 16
	ramdiskFallbackGB = 4

	tmpfs512M = "size=512M,mode=1777"
)

// LogFunc receives runtime setup diagnostics.
type LogFunc func(format string, args ...any)

type sysctlSetting struct {
	path     string
	value    string
	optional bool
}

// sysctlPolicy is compiled into the measured PID 1 binary. Keeping the exact
// procfs paths here avoids shipping a configuration-language parser.
var sysctlPolicy = []sysctlSetting{
	{path: "fs/protected_hardlinks", value: "1"},
	{path: "fs/protected_symlinks", value: "1"},
	{path: "fs/protected_regular", value: "2"},
	{path: "fs/protected_fifos", value: "1"},
	{path: "kernel/dmesg_restrict", value: "1"},
	{path: "kernel/kptr_restrict", value: "1"},
	{path: "kernel/oops_limit", value: "1"},
	{path: "kernel/panic_on_oops", value: "1"},
	{path: "kernel/panic_on_warn", value: "0"},
	{path: "kernel/perf_event_paranoid", value: "4"},
	{path: "kernel/printk", value: "4 4 1 7"},
	{path: "kernel/unprivileged_bpf_disabled", value: "1"},
	{path: "kernel/unprivileged_userns_clone", value: "0"},
	{path: "kernel/warn_limit", value: "10"},
	{path: "kernel/yama/ptrace_scope", value: "1"},
	{path: "net/core/bpf_jit_harden", value: "2"},
	{path: "net/core/default_qdisc", value: "fq_codel", optional: true},
	{path: "net/ipv4/conf/default/rp_filter", value: "2"},
	{path: "net/ipv4/conf/all/rp_filter", value: "2"},
	{path: "vm/max_map_count", value: "1048576"},
	{path: "vm/mmap_min_addr", value: "65536"},
}

// SetupFilesystems mounts the kernel-backed filesystems and creates the
// runtime paths required before services start.
func SetupFilesystems(log LogFunc) error {
	if err := os.WriteFile("/proc/sys/kernel/hostname", []byte("tinfoil\n"), 0644); err != nil {
		logf(log, "warning: setting hostname: %v", err)
	}
	mounts := []struct {
		source string
		target string
		fstype string
		flags  uintptr
		data   string
		fatal  bool
	}{
		{"tmpfs", "/dev/shm", "tmpfs", syscall.MS_NOSUID | syscall.MS_NODEV, "mode=1777,size=512M", true},
		{"devpts", "/dev/pts", "devpts", syscall.MS_NOSUID | syscall.MS_NOEXEC, "mode=0620,ptmxmode=0666,newinstance", true},
		{"mqueue", "/dev/mqueue", "mqueue", syscall.MS_NOSUID | syscall.MS_NODEV | syscall.MS_NOEXEC, "", false},
		{"hugetlbfs", "/dev/hugepages", "hugetlbfs", syscall.MS_NOSUID | syscall.MS_NODEV, "mode=1770,gid=0", false},
		{"cgroup2", "/sys/fs/cgroup", "cgroup2", syscall.MS_NOSUID | syscall.MS_NODEV | syscall.MS_NOEXEC, "", true},
	}
	for _, mount := range mounts {
		if err := mountIfNeeded(mount.source, mount.target, mount.fstype, mount.flags, mount.data, log); err != nil {
			if mount.fatal {
				return err
			}
			logf(log, "optional mount skipped: %v", err)
		}
	}
	if err := ensureSymlink("/dev/shm", "/run/shm"); err != nil {
		logf(log, "warning: creating /run/shm compatibility symlink: %v", err)
	}
	for _, dir := range []struct {
		path string
		mode os.FileMode
	}{
		{"/run/lock", os.ModeSticky | 0777},
		{"/run/cryptsetup", 0700},
	} {
		if err := ensureDir(dir.path, dir.mode); err != nil {
			logf(log, "warning: creating runtime dir %s: %v", dir.path, err)
		}
	}
	return nil
}

// SetupRamdisk mounts the workload ramdisk and private/public subdirectories.
func SetupRamdisk(log LogFunc) error {
	logf(log, "creating ramdisk")
	memTotalKB, err := systemMemoryKB()
	if err != nil {
		return fmt.Errorf("reading system memory: %w", err)
	}
	sizeGB, fallback, err := ramdiskSizeGB(memTotalKB)
	if err != nil {
		return fmt.Errorf("sizing ramdisk: %w", err)
	}
	if fallback {
		logf(log, "warning: not enough RAM for full ramdisk, falling back to %dG", sizeGB)
	}

	if err := mountIfNeeded("tmpfs", boot.RamdiskDir, "tmpfs", syscall.MS_NOSUID|syscall.MS_NODEV, fmt.Sprintf("size=%dG,mode=0755", sizeGB), log); err != nil {
		return err
	}
	if err := ensureDir(boot.PrivateDir, 0700); err != nil {
		return err
	}
	if err := ensureDir(boot.PublicDir, 0755); err != nil {
		return err
	}
	if err := mountIfNeeded("tmpfs", "/tmp", "tmpfs", syscall.MS_NOSUID|syscall.MS_NODEV, tmpfs512M, log); err != nil {
		return err
	}
	if err := mountIfNeeded("tmpfs", "/var/tmp", "tmpfs", syscall.MS_NOSUID|syscall.MS_NODEV, tmpfs512M, log); err != nil {
		return err
	}
	logf(log, "ramdisk ready")
	return nil
}

// ApplySysctls applies the measured runtime sysctl policy.
func ApplySysctls(log LogFunc) error {
	return applySysctls("/proc/sys", sysctlPolicy, log)
}

func systemMemoryKB() (uint64, error) {
	var info unix.Sysinfo_t
	if err := unix.Sysinfo(&info); err != nil {
		return 0, err
	}
	return memoryKB(uint64(info.Totalram), uint64(info.Unit))
}

func memoryKB(totalRAM, unit uint64) (uint64, error) {
	if totalRAM == 0 {
		return 0, errors.New("total RAM is zero")
	}
	if unit == 0 {
		unit = 1
	}
	if totalRAM > ^uint64(0)/unit {
		return 0, errors.New("total RAM overflows bytes")
	}
	return totalRAM * unit / 1024, nil
}

func ramdiskSizeGB(memTotalKB uint64) (uint64, bool, error) {
	if memTotalKB == 0 {
		return 0, false, errors.New("MemTotal is zero")
	}
	ramGB := memTotalKB / 1024 / 1024
	if ramGB < ramdiskMinRAMGB {
		return ramdiskFallbackGB, true, nil
	}
	return ramGB - ramdiskReserveGB, false, nil
}

func mountIfNeeded(source, target, fstype string, flags uintptr, data string, log LogFunc) error {
	if isMountPoint(target) {
		return nil
	}
	if err := os.MkdirAll(target, 0755); err != nil {
		return err
	}
	if err := syscall.Mount(source, target, fstype, flags, data); err != nil {
		return fmt.Errorf("mount %s on %s: %w", fstype, target, err)
	}
	logf(log, "mounted %s on %s", fstype, target)
	return nil
}

func ensureDir(path string, mode os.FileMode) error {
	if err := os.MkdirAll(path, mode); err != nil {
		return err
	}
	if err := os.Chmod(path, mode); err != nil {
		return fmt.Errorf("chmod %s: %w", path, err)
	}
	return nil
}

func ensureSymlink(target, linkPath string) error {
	info, err := os.Lstat(linkPath)
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			current, err := os.Readlink(linkPath)
			if err != nil {
				return fmt.Errorf("readlink %s: %w", linkPath, err)
			}
			if current == target {
				return nil
			}
			if err := os.Remove(linkPath); err != nil {
				return fmt.Errorf("remove stale symlink %s: %w", linkPath, err)
			}
		} else if err := os.Remove(linkPath); err != nil {
			return fmt.Errorf("%s exists and is not removable: %w", linkPath, err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(linkPath), 0755); err != nil {
		return err
	}
	if err := os.Symlink(target, linkPath); err != nil {
		return fmt.Errorf("symlink %s -> %s: %w", linkPath, target, err)
	}
	return nil
}

func isMountPoint(target string) bool {
	target = filepath.Clean(target)
	parent := filepath.Dir(target)
	var targetStat, parentStat unix.Statx_t
	if err := unix.Statx(unix.AT_FDCWD, target, unix.AT_SYMLINK_NOFOLLOW, unix.STATX_MNT_ID, &targetStat); err != nil {
		return false
	}
	if err := unix.Statx(unix.AT_FDCWD, parent, unix.AT_SYMLINK_NOFOLLOW, unix.STATX_MNT_ID, &parentStat); err != nil {
		return false
	}
	return targetStat.Mask&unix.STATX_MNT_ID != 0 &&
		parentStat.Mask&unix.STATX_MNT_ID != 0 &&
		targetStat.Mnt_id != parentStat.Mnt_id
}

func applySysctls(procSysRoot string, policy []sysctlSetting, log LogFunc) error {
	for _, setting := range policy {
		procPath := filepath.Join(procSysRoot, setting.path)
		if err := os.WriteFile(procPath, []byte(setting.value+"\n"), 0644); err != nil {
			if setting.optional && errors.Is(err, os.ErrNotExist) {
				logf(log, "optional sysctl %s skipped: %v", setting.path, err)
				continue
			}
			return fmt.Errorf("setting sysctl %s: %w", setting.path, err)
		}
		actual, err := os.ReadFile(procPath)
		if err != nil {
			return fmt.Errorf("verifying sysctl %s: %w", setting.path, err)
		}
		if normalizeSysctlValue(string(actual)) != normalizeSysctlValue(setting.value) {
			return fmt.Errorf("verifying sysctl %s: read %q after writing %q", setting.path, strings.TrimSpace(string(actual)), setting.value)
		}
	}
	logf(log, "applied sysctl policy")
	return nil
}

func normalizeSysctlValue(value string) string {
	return strings.Join(strings.Fields(value), " ")
}

func logf(log LogFunc, format string, args ...any) {
	if log != nil {
		log(format, args...)
	}
}
