package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"tinfoil/internal/boot"
)

const (
	// Boot timing budget.
	bootTimeout            = 5 * time.Minute
	defaultStartTimeout    = 60 * time.Second
	containerdSocketWait   = 30 * time.Second
	dockerSocketWait       = 60 * time.Second
	persistencedSocketWait = 5 * time.Second
	nvmlReadyTimeout       = 15 * time.Second
	optionalCommandTimeout = 20 * time.Second

	// NVIDIA CC (B300) bring-up timing gates. Empirical values from the
	// INF12/INF14 B300 full-CC bring-up: probing the driver too early after
	// guest boot, or opening RM/NVML too soon after module load,
	// intermittently failed while GPU firmware was still settling after
	// reset. These are open-loop waits because no guest-observable readiness
	// signal has been identified yet; replacing them with condition polls is
	// tracked as a follow-up (needs hardware revalidation).
	nvidiaMinProbeUptime = 17 * time.Second // minimum uptime before first driver probe
	nvidiaPreRMOpenWait  = 5 * time.Second  // settle before the first RM/NVML open
	nvidiaCoreModuleWait = 4 * time.Second  // settle after core module before uvm/modeset

	nvidiaPreRMOpenShell    = "tinfoil-nvidia-pre-open-shell=on"
	nvidiaSkipPCIEnableHold = "tinfoil-nvidia-skip-pci-enable-hold=on"

	// PCI config-space offsets and masks, named as in the kernel's
	// include/uapi/linux/pci_regs.h.
	pciCommandOffset      = 4    // PCI_COMMAND
	pciStatusOffset       = 6    // PCI_STATUS
	pciHeaderTypeOffset   = 0x0e // PCI_HEADER_TYPE
	pciHeaderTypeMask     = 0x7f // PCI_HEADER_TYPE_MASK
	pciCapabilityPtrType0 = 0x34 // PCI_CAPABILITY_LIST (type 0 header)
	pciCapPtrAlignMask    = 0x03 // capability pointers are dword-aligned
	pciStdHeaderSize      = 0x40 // PCI_STD_HEADER_SIZEOF: capabilities live above it
	pciConfigSnapshotLen  = 256
	pciCommandINTxDisable = 1 << 10 // PCI_COMMAND_INTX_DISABLE
	pciStatusCapabilities = 1 << 4  // PCI_STATUS_CAP_LIST
	pciCapabilityMSI      = 0x05    // PCI_CAP_ID_MSI
	pciCapabilityMSIX     = 0x11    // PCI_CAP_ID_MSIX
	msixCtrlEnable        = 0x8000  // PCI_MSIX_FLAGS_ENABLE
	msixCtrlFuncMask      = 0x4000  // PCI_MSIX_FLAGS_MASKALL
	// Bound on capability-chain walks; belt-and-braces with the seen-map
	// (a 256-byte type-0 config space fits at most ~48 2-byte entries).
	maxPCICapabilities = 48

	// PCI class codes as exposed by sysfs "class".
	pciClassVGAController = "0x030000"
	pciClass3DController  = "0x030200"

	// Fixed NVIDIA control-node minors defined by the NVIDIA kernel driver
	// (nv.h: NV_CONTROL_DEVICE_MINOR 255, modeset 254; nvidia-uvm uses minor
	// 0 and nvidia-uvm-tools minor 1 on the nvidia-uvm major).
	nvidiaCtlMinor      = 255
	nvidiaModesetMinor  = 254
	nvidiaUVMMinor      = 0
	nvidiaUVMToolsMinor = 1

	dockerSocket        = "/run/docker.sock"
	containerdSocket    = "/run/containerd/containerd.sock"
	sysctlRuntimeConf   = "/usr/lib/sysctl.d/tinfoil-runtime.conf"
	tinfoilPID1Env      = "TINFOIL_PID1"
	tinfoilPID1EnvValue = "tinfoil-init"
	nvidiaRMTraceLogEnv = "TINFOIL_NVIDIA_RM_TRACE_LOG"
	selfExecPath        = "/proc/self/exe"
	containerStatusName = "tinfoil-container-status"
	egressName          = "tinfoil-egress"
	shimName            = "tinfoil-shim"
	runtimeNOFILELimit  = 524288

	// Ramdisk sizing policy (preserves the legacy tinfoil-ramdisk script):
	// hosts with at least ramdiskMinRAMGB keep ramdiskReserveGB for the OS
	// and give the rest to the ramdisk; smaller dev hosts fall back to
	// ramdiskFallbackGB.
	ramdiskMinRAMGB   = 32
	ramdiskReserveGB  = 16
	ramdiskFallbackGB = 4

	tmpfs512M = "size=512M,mode=1777"
)

var consoleMu sync.Mutex

type runtimeResourceLimit struct {
	name     string
	resource int
	soft     uint64
	hard     uint64
}

var runtimeResourceLimits = []runtimeResourceLimit{
	{name: "nofile", resource: unix.RLIMIT_NOFILE, soft: runtimeNOFILELimit, hard: runtimeNOFILELimit},
	{name: "memlock", resource: unix.RLIMIT_MEMLOCK, soft: unix.RLIM_INFINITY, hard: unix.RLIM_INFINITY},
}

var pciDevicesDir = "/sys/bus/pci/devices"
var nvidiaGPUsDir = "/proc/driver/nvidia/gpus"
var nvidiaCapabilitiesDir = "/proc/driver/nvidia/capabilities"
var nvidiaPersistencedRunDir = "/run/nvidia-persistenced"
var nvidiaPersistencedSocket = "/run/nvidia-persistenced/socket"
var nvidiaPersistencedPIDPath = "/run/nvidia-persistenced/nvidia-persistenced.pid"
var nvidiaRMTraceLibrary = "/usr/lib/tinfoil/nvidia-rm-trace.so"
var nvidiaRMTraceLog = "/run/nvidia-persistenced/rm-trace.log"
var nvidiaCDIPath = "/var/run/cdi/nvidia.yaml"
var procCmdlinePath = "/proc/cmdline"
var procDevicesPath = "/proc/devices"
var procMeminfoPath = "/proc/meminfo"
var procUptimePath = "/proc/uptime"
var consolePath = "/dev/console"
var devRootDir = "/dev"
var devLogPath = "/dev/log"
var passwdPath = "/etc/passwd"

type managedProcess struct {
	name     string
	path     string
	args     []string
	required bool
	restart  bool
	harden   string
	cmd      *exec.Cmd
}

type serviceHardening struct {
	noNewPrivileges bool
	boundCaps       []int
}

var serviceHardeningPolicy = map[string]serviceHardening{
	"tinfoil-boot":      {noNewPrivileges: true},
	containerStatusName: {noNewPrivileges: true, boundCaps: []int{}},
	egressName:          {noNewPrivileges: true, boundCaps: []int{unix.CAP_NET_ADMIN}},
	shimName:            {noNewPrivileges: true, boundCaps: []int{unix.CAP_NET_BIND_SERVICE}},
}

func main() {
	log.SetFlags(0)
	if len(os.Args) > 1 && os.Args[1] == "--exec-service" {
		if err := execService(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "tinfoil-init: exec-service: %v\n", err)
			os.Exit(127)
		}
		panic("unreachable")
	}

	os.Setenv("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
	os.Setenv(tinfoilPID1Env, tinfoilPID1EnvValue)

	if os.Getpid() != 1 {
		initLogf("warning: running with pid %d, expected pid 1", os.Getpid())
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := run(ctx); err != nil {
		initLogf("fatal: %v", err)
		for {
			time.Sleep(time.Minute)
		}
	}
}

func run(parent context.Context) error {
	// bootCtx bounds only the startup sequence. Service supervision and the
	// final lifecycle wait must use parent (cancelled only by signals):
	// tying them to the boot deadline would stop restarts and shut the CVM
	// down bootTimeout after a successful boot.
	bootCtx, cancelBoot := bootContext(parent)
	defer cancelBoot()

	initLogf("starting")
	if err := setupRuntimeFilesystems(); err != nil {
		return err
	}
	if err := applyRuntimeResourceLimits(); err != nil {
		return err
	}
	if err := loadDockerKernelModules(); err != nil {
		return fmt.Errorf("loading Docker kernel modules: %w", err)
	}
	if err := applySysctls(sysctlRuntimeConf); err != nil {
		return err
	}

	if err := setupRamdisk(); err != nil {
		return err
	}
	if err := runOneShot(bootCtx, defaultStartTimeout, "/usr/sbin/nft", "-f", "/etc/nftables.conf"); err != nil {
		return err
	}

	startOptionalNVIDIA(bootCtx, parent)

	containerd, err := startManaged(parent, &managedProcess{
		name:     "containerd",
		path:     "/usr/bin/containerd",
		required: true,
		restart:  true,
	})
	if err != nil {
		return err
	}
	if err := waitForPath(bootCtx, containerdSocket, containerdSocketWait); err != nil {
		return fmt.Errorf("waiting for containerd socket: %w", err)
	}

	dockerd, err := startManaged(parent, &managedProcess{
		name:     "dockerd",
		path:     "/usr/bin/dockerd",
		args:     []string{"-H", "unix://" + dockerSocket, "--containerd=" + containerdSocket},
		required: true,
		restart:  true,
	})
	if err != nil {
		return err
	}
	if err := waitForPath(bootCtx, dockerSocket, dockerSocketWait); err != nil {
		return fmt.Errorf("waiting for Docker socket: %w", err)
	}

	if err := runOneShotHardened(bootCtx, tinfoilBootTimeout(), "tinfoil-boot", boot.BootBinary); err != nil {
		stopProcess(dockerd)
		stopProcess(containerd)
		return err
	}

	if _, err := startManaged(parent, &managedProcess{name: containerStatusName, path: boot.ContainerStatusBinary, restart: true, harden: containerStatusName}); err != nil {
		return err
	}
	if _, err := startManaged(parent, &managedProcess{name: shimName, path: boot.ShimBinary, required: true, restart: true, harden: shimName}); err != nil {
		return err
	}
	if _, err := os.Stat(boot.EgressConfigPath); err == nil {
		if _, err := startManaged(parent, &managedProcess{name: egressName, path: boot.EgressBinary, restart: true, harden: egressName}); err != nil {
			return err
		}
	}

	initLogf("boot complete")
	cancelBoot()
	<-parent.Done()
	initLogf("shutdown requested")
	return nil
}

func setupRuntimeFilesystems() error {
	if err := os.WriteFile("/proc/sys/kernel/hostname", []byte("tinfoil\n"), 0644); err != nil {
		initLogf("warning: setting hostname: %v", err)
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
		// devpts 0620/ptmx 0666 is the conventional pty layout (group-write
		// for the tty group); hugetlbfs 1770 gid=0 keeps hugepages
		// root-group-only with the sticky bit, matching systemd defaults.
		{"devpts", "/dev/pts", "devpts", syscall.MS_NOSUID | syscall.MS_NOEXEC, "mode=0620,ptmxmode=0666,newinstance", true},
		{"mqueue", "/dev/mqueue", "mqueue", syscall.MS_NOSUID | syscall.MS_NODEV | syscall.MS_NOEXEC, "", false},
		{"hugetlbfs", "/dev/hugepages", "hugetlbfs", syscall.MS_NOSUID | syscall.MS_NODEV, "mode=1770,gid=0", false},
		{"cgroup2", "/sys/fs/cgroup", "cgroup2", syscall.MS_NOSUID | syscall.MS_NODEV | syscall.MS_NOEXEC, "", true},
	}
	for _, m := range mounts {
		if err := mountIfNeeded(m.source, m.target, m.fstype, m.flags, m.data); err != nil {
			if m.fatal {
				return err
			}
			initLogf("optional mount skipped: %v", err)
		}
	}
	if err := ensureSymlink("/dev/shm", "/run/shm"); err != nil {
		initLogf("warning: creating /run/shm compatibility symlink: %v", err)
	}
	return nil
}

func setupRamdisk() error {
	initLogf("creating ramdisk")
	sizeGB, fallback, err := ramdiskSizeGBFrom(procMeminfoPath)
	if err != nil {
		return fmt.Errorf("sizing ramdisk: %w", err)
	}
	if fallback {
		initLogf("warning: not enough RAM for full ramdisk, falling back to %dG", sizeGB)
	}

	if err := mountIfNeeded("tmpfs", boot.RamdiskDir, "tmpfs", syscall.MS_NOSUID|syscall.MS_NODEV, fmt.Sprintf("size=%dG,mode=0755", sizeGB)); err != nil {
		return err
	}
	if err := ensureDir(boot.PrivateDir, 0700); err != nil {
		return err
	}
	if err := ensureDir(boot.PublicDir, 0755); err != nil {
		return err
	}
	if err := mountIfNeeded("tmpfs", "/tmp", "tmpfs", syscall.MS_NOSUID|syscall.MS_NODEV, tmpfs512M); err != nil {
		return err
	}
	if err := mountIfNeeded("tmpfs", "/var/tmp", "tmpfs", syscall.MS_NOSUID|syscall.MS_NODEV, tmpfs512M); err != nil {
		return err
	}
	initLogf("ramdisk ready")
	return nil
}

func ramdiskSizeGBFrom(path string) (uint64, bool, error) {
	memTotalKB, err := readMemTotalKB(path)
	if err != nil {
		return 0, false, err
	}
	return ramdiskSizeGB(memTotalKB)
}

func readMemTotalKB(path string) (uint64, error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 2 && fields[0] == "MemTotal:" {
			value, err := strconv.ParseUint(fields[1], 10, 64)
			if err != nil {
				return 0, fmt.Errorf("parse MemTotal %q: %w", fields[1], err)
			}
			return value, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, err
	}
	return 0, errors.New("MemTotal not found")
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

func mountIfNeeded(source, target, fstype string, flags uintptr, data string) error {
	if isMountPoint(target) {
		return nil
	}
	if err := os.MkdirAll(target, 0755); err != nil {
		return err
	}
	if err := syscall.Mount(source, target, fstype, flags, data); err != nil {
		return fmt.Errorf("mount %s on %s: %w", fstype, target, err)
	}
	initLogf("mounted %s on %s", fstype, target)
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
		} else {
			if err := os.Remove(linkPath); err != nil {
				return fmt.Errorf("%s exists and is not an empty removable path: %w", linkPath, err)
			}
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
	initLogf("created symlink %s -> %s", linkPath, target)
	return nil
}

func isMountPoint(target string) bool {
	file, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return false
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 5 && fields[4] == target {
			return true
		}
	}
	return false
}

func applyRuntimeResourceLimits() error {
	for _, limit := range runtimeResourceLimits {
		var before unix.Rlimit
		if err := unix.Getrlimit(limit.resource, &before); err != nil {
			return fmt.Errorf("get rlimit %s: %w", limit.name, err)
		}
		desired := desiredRaisedRlimit(before, limit.soft, limit.hard)
		if desired != before {
			if err := unix.Setrlimit(limit.resource, &desired); err != nil {
				return fmt.Errorf("set rlimit %s soft=%s hard=%s: %w", limit.name, formatRlimitValue(desired.Cur), formatRlimitValue(desired.Max), err)
			}
		}
		var after unix.Rlimit
		if err := unix.Getrlimit(limit.resource, &after); err != nil {
			return fmt.Errorf("verify rlimit %s: %w", limit.name, err)
		}
		if after.Cur < limit.soft || after.Max < limit.hard {
			return fmt.Errorf("rlimit %s stayed below requested floor: soft=%s hard=%s want soft>=%s hard>=%s", limit.name, formatRlimitValue(after.Cur), formatRlimitValue(after.Max), formatRlimitValue(limit.soft), formatRlimitValue(limit.hard))
		}
		initLogf("runtime resource limit %s: soft %s -> %s, hard %s -> %s", limit.name, formatRlimitValue(before.Cur), formatRlimitValue(after.Cur), formatRlimitValue(before.Max), formatRlimitValue(after.Max))
	}
	return nil
}

func desiredRaisedRlimit(current unix.Rlimit, soft, hard uint64) unix.Rlimit {
	desired := current
	hardFloor := hard
	if soft > hardFloor {
		hardFloor = soft
	}
	if desired.Max < hardFloor {
		desired.Max = hardFloor
	}
	if desired.Cur < soft {
		desired.Cur = soft
	}
	return desired
}

func formatRlimitValue(value uint64) string {
	if value == unix.RLIM_INFINITY {
		return "infinity"
	}
	return strconv.FormatUint(value, 10)
}

func applySysctls(path string) error {
	// The sysctl policy is baked into the measured image; a missing file can
	// only mean a build regression, so fail closed instead of booting with
	// kernel-default (unhardened) sysctls.
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("opening sysctl config: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		ignoreMissing := strings.HasPrefix(line, "-")
		line = strings.TrimPrefix(line, "-")
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return fmt.Errorf("invalid sysctl line %q", line)
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		procPath := filepath.Join("/proc/sys", strings.ReplaceAll(key, ".", "/"))
		if err := os.WriteFile(procPath, []byte(value+"\n"), 0644); err != nil {
			if ignoreMissing || errors.Is(err, os.ErrNotExist) {
				initLogf("sysctl %s skipped: %v", key, err)
				continue
			}
			return fmt.Errorf("setting sysctl %s: %w", key, err)
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	initLogf("applied sysctl policy")
	return nil
}

// startOptionalNVIDIA runs the bounded NVIDIA bootstrap. ctx carries the boot
// deadline; superviseCtx outlives boot and controls long-lived helpers (the
// syslog sink goroutine), which must not stop when the boot budget expires.
func startOptionalNVIDIA(ctx, superviseCtx context.Context) {
	if !hasNVIDIAPCIDevice() {
		initLogf("NVIDIA services skipped: no NVIDIA PCI device")
		return
	}
	initLogf("NVIDIA PCI device detected; running bounded NVIDIA bootstrap")
	if bootDebugEnabled() {
		logRuntimeEnvironmentDiagnostics("before-nvidia-bootstrap")
	}
	waitForNVIDIAPreProbeUptime(ctx)
	if nvidiaPCIEnableHoldDisabled() {
		initLogf("NVIDIA PCI enable reference hold skipped by debug cmdline flag")
	} else if err := holdNVIDIAPCIEnableReference(); err != nil {
		initLogf("warning: holding NVIDIA PCI enable reference: %v", err)
	}
	if err := enableNVIDIARuntimePowerManagement(); err != nil {
		initLogf("warning: enabling NVIDIA runtime power management before driver probe: %v", err)
	}
	if err := loadNVIDIAPrerequisiteKernelModules(); err != nil {
		initLogf("warning: loading NVIDIA prerequisite kernel modules: %v", err)
	}
	if err := loadNVIDIACoreKernelModules(); err != nil {
		initLogf("warning: loading NVIDIA core kernel modules: %v", err)
	}
	logNVIDIACoreModuleDiagnostics("before-settle")
	waitForNVIDIACoreModuleSettle(ctx)
	logNVIDIACoreModuleDiagnostics("after-settle")
	if _, err := os.Stat(nvidiaGPUsDir); err != nil {
		initLogf("NVIDIA services skipped: driver state not ready after module bootstrap: %v", err)
		return
	}
	if err := enableNVIDIARuntimePowerManagement(); err != nil {
		initLogf("warning: enabling NVIDIA runtime power management: %v", err)
	}
	if err := loadNVIDIAUVMKernelModules(); err != nil {
		initLogf("warning: loading NVIDIA UVM kernel modules: %v", err)
	}
	setupNVIDIADeviceFiles()
	startOptionalNVIDIAFabricManager(ctx)
	startOptionalSyslogSink(superviseCtx)
	logNVIDIAPreRMOpenDiagnostics("before-settle")
	waitForNVIDIAPreRMOpenSettle(ctx)
	logNVIDIAPreRMOpenDiagnostics("after-settle")
	maybeRunNVIDIAPreRMOpenDebugShell(ctx)
	startNVIDIAPersistenced(ctx)
	if err := waitForNVIDIANVML(ctx, nvmlReadyTimeout); err != nil {
		initLogf("warning: waiting for NVIDIA NVML readiness: %v", err)
		logNVIDIARMTraceLog("after-nvml-wait")
	}
	if err := loadNVIDIAModesetKernelModules(); err != nil {
		initLogf("warning: loading NVIDIA modeset kernel modules: %v", err)
	}
	setupNVIDIADeviceFiles()
	if err := os.MkdirAll(filepath.Dir(nvidiaCDIPath), 0755); err != nil {
		initLogf("warning: creating NVIDIA CDI dir: %v", err)
	} else {
		runOptional(ctx, "/usr/bin/nvidia-ctk", "cdi", "generate", "--output="+nvidiaCDIPath)
	}
	if bootDebugEnabled() {
		logNVIDIADebugDiagnostics(ctx)
	}
}

func waitForNVIDIAPreProbeUptime(ctx context.Context) {
	uptime, err := readSystemUptime(procUptimePath)
	if err != nil {
		initLogf("warning: reading uptime before NVIDIA probe: %v", err)
		return
	}
	if uptime >= nvidiaMinProbeUptime {
		initLogf("NVIDIA pre-probe uptime gate skipped: uptime %s >= %s", uptime.Round(time.Millisecond), nvidiaMinProbeUptime)
		return
	}
	wait := nvidiaMinProbeUptime - uptime
	initLogf("waiting %s before NVIDIA driver probe: uptime %s < %s", wait.Round(time.Millisecond), uptime.Round(time.Millisecond), nvidiaMinProbeUptime)
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		initLogf("NVIDIA pre-probe uptime gate interrupted: %v", ctx.Err())
	case <-timer.C:
		initLogf("NVIDIA pre-probe uptime gate complete")
	}
}

func readSystemUptime(path string) (time.Duration, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return 0, fmt.Errorf("%s is empty", path)
	}
	seconds, err := strconv.ParseFloat(fields[0], 64)
	if err != nil || seconds < 0 {
		return 0, fmt.Errorf("invalid uptime %q in %s", fields[0], path)
	}
	return time.Duration(seconds * float64(time.Second)), nil
}

func setupNVIDIADeviceFiles() {
	if err := ensureNVIDIADeviceNodes(); err != nil {
		initLogf("warning: creating NVIDIA device nodes: %v", err)
	}
}

func waitForNVIDIACoreModuleSettle(ctx context.Context) {
	initLogf("waiting %s after NVIDIA core module before modeset/uvm", nvidiaCoreModuleWait)
	timer := time.NewTimer(nvidiaCoreModuleWait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		initLogf("NVIDIA core module settle interrupted: %v", ctx.Err())
	case <-timer.C:
		initLogf("NVIDIA core module settle complete")
	}
}

func logNVIDIACoreModuleDiagnostics(stage string) {
	initLogf("NVIDIA core module diagnostics %s begin", stage)
	logNVIDIAPCIState()
	logReadableFile("NVIDIA driver params", "/proc/driver/nvidia/params", nil)
	logReadableGlob("NVIDIA GPU information", filepath.Join(nvidiaGPUsDir, "*", "information"))
	logReadableGlob("NVIDIA GPU power", filepath.Join(nvidiaGPUsDir, "*", "power"))
	logReadableGlob("NVIDIA GPU registry", filepath.Join(nvidiaGPUsDir, "*", "registry"))
	logKernelRingFiltered("kernel NVIDIA core diagnostics", func(line string) bool {
		lower := strings.ToLower(line)
		return strings.Contains(lower, "nvidia") ||
			strings.Contains(lower, "nvrm") ||
			strings.Contains(lower, "gsp") ||
			strings.Contains(lower, "gpu firmware") ||
			strings.Contains(lower, "rminit") ||
			strings.Contains(lower, "xid")
	})
	initLogf("NVIDIA core module diagnostics %s end", stage)
}

func waitForNVIDIAPreRMOpenSettle(ctx context.Context) {
	initLogf("waiting %s for NVIDIA driver settle before first RM open", nvidiaPreRMOpenWait)
	timer := time.NewTimer(nvidiaPreRMOpenWait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		initLogf("NVIDIA pre-RM-open settle interrupted: %v", ctx.Err())
	case <-timer.C:
		initLogf("NVIDIA pre-RM-open settle complete")
	}
}

func logNVIDIAPreRMOpenDiagnostics(stage string) {
	initLogf("NVIDIA pre-RM-open diagnostics %s begin", stage)
	logNVIDIAPCIState()
	logReadableFile("NVIDIA driver params", "/proc/driver/nvidia/params", nil)
	logReadableGlob("NVIDIA GPU information", filepath.Join(nvidiaGPUsDir, "*", "information"))
	logReadableGlob("NVIDIA GPU power", filepath.Join(nvidiaGPUsDir, "*", "power"))
	logReadableGlob("NVIDIA GPU registry", filepath.Join(nvidiaGPUsDir, "*", "registry"))
	logNVIDIADeviceStats()
	logKernelRingFiltered("kernel GPU pre-RM diagnostics", func(line string) bool {
		lower := strings.ToLower(line)
		return strings.Contains(lower, "nvidia") ||
			strings.Contains(lower, "nvrm") ||
			strings.Contains(lower, "gsp") ||
			strings.Contains(lower, "gpu firmware") ||
			strings.Contains(lower, "xid")
	})
	initLogf("NVIDIA pre-RM-open diagnostics %s end", stage)
}

func startNVIDIAPersistenced(ctx context.Context) {
	if _, err := os.Stat("/usr/bin/nvidia-persistenced"); err != nil {
		return
	}
	if err := prepareNVIDIAPersistencedRuntime(); err != nil {
		initLogf("warning: preparing nvidia-persistenced runtime: %v", err)
	}
	if bootDebugEnabled() {
		logRuntimeEnvironmentDiagnostics("before-nvidia-persistenced")
	}
	env := childEnv()
	if nvidiaRMTraceEnabled() {
		initLogf("NVIDIA RM trace enabled for nvidia-persistenced at %s", nvidiaRMTraceLog)
		env = withNVIDIARMTraceEnv(env)
	}
	if err := runOneShotEnv(ctx, defaultStartTimeout, env, "/usr/bin/nvidia-persistenced", "--user", "nvidia-persistenced", "--uvm-persistence-mode", "--verbose"); err != nil {
		initLogf("warning: starting nvidia-persistenced: %v", err)
		logNVIDIARMTraceLog("after-persistenced-start")
		return
	}
	logNVIDIARMTraceLog("after-persistenced-start")
	if bootDebugEnabled() {
		logNVIDIAPersistencedProcessDiagnostics("after-persistenced-start")
	}
	if err := waitForPath(ctx, nvidiaPersistencedSocket, persistencedSocketWait); err != nil {
		initLogf("warning: waiting for nvidia-persistenced socket: %v", err)
	}
}

func prepareNVIDIAPersistencedRuntime() error {
	uid, gid, err := lookupPasswdUser("nvidia-persistenced")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(nvidiaPersistencedRunDir, 0755); err != nil {
		return fmt.Errorf("mkdir %s: %w", nvidiaPersistencedRunDir, err)
	}
	if err := os.Chown(nvidiaPersistencedRunDir, uid, gid); err != nil {
		return fmt.Errorf("chown %s: %w", nvidiaPersistencedRunDir, err)
	}
	if err := os.Chmod(nvidiaPersistencedRunDir, 0755); err != nil {
		return fmt.Errorf("chmod %s: %w", nvidiaPersistencedRunDir, err)
	}
	if err := os.Remove(nvidiaPersistencedSocket); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove stale %s: %w", nvidiaPersistencedSocket, err)
	}
	if err := os.Remove(nvidiaPersistencedPIDPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove stale %s: %w", nvidiaPersistencedPIDPath, err)
	}
	if err := os.Remove(nvidiaRMTraceLog); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove stale %s: %w", nvidiaRMTraceLog, err)
	}
	if nvidiaRMTraceEnabled() {
		file, err := os.OpenFile(nvidiaRMTraceLog, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
		if err != nil {
			return fmt.Errorf("create %s: %w", nvidiaRMTraceLog, err)
		}
		if err := file.Close(); err != nil {
			return fmt.Errorf("close %s: %w", nvidiaRMTraceLog, err)
		}
		if err := os.Chown(nvidiaRMTraceLog, uid, gid); err != nil {
			return fmt.Errorf("chown %s: %w", nvidiaRMTraceLog, err)
		}
	}
	return nil
}

func lookupPasswdUser(name string) (int, int, error) {
	file, err := os.Open(passwdPath)
	if err != nil {
		return 0, 0, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), ":")
		if len(fields) < 4 || fields[0] != name {
			continue
		}
		uid, err := strconv.Atoi(fields[2])
		if err != nil {
			return 0, 0, fmt.Errorf("invalid uid for %s: %w", name, err)
		}
		gid, err := strconv.Atoi(fields[3])
		if err != nil {
			return 0, 0, fmt.Errorf("invalid gid for %s: %w", name, err)
		}
		return uid, gid, nil
	}
	if err := scanner.Err(); err != nil {
		return 0, 0, err
	}
	return 0, 0, fmt.Errorf("user %s not found in %s", name, passwdPath)
}

func startOptionalSyslogSink(ctx context.Context) {
	if _, err := os.Lstat(devLogPath); err == nil {
		initLogf("syslog sink skipped: %s already exists", devLogPath)
		return
	} else if !errors.Is(err, os.ErrNotExist) {
		initLogf("warning: checking %s: %v", devLogPath, err)
		return
	}
	if err := startSyslogSink(ctx, devLogPath); err != nil {
		initLogf("warning: starting syslog sink: %v", err)
	}
}

func startSyslogSink(ctx context.Context, path string) error {
	addr := &net.UnixAddr{Name: path, Net: "unixgram"}
	conn, err := net.ListenUnixgram("unixgram", addr)
	if err != nil {
		return err
	}
	if err := os.Chmod(path, 0666); err != nil {
		conn.Close()
		return err
	}
	initLogf("started syslog sink at %s", path)
	go func() {
		defer conn.Close()
		buf := make([]byte, 8192)
		for {
			if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
				initLogf("syslog sink deadline failed: %v", err)
				return
			}
			n, _, err := conn.ReadFromUnix(buf)
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					select {
					case <-ctx.Done():
						return
					default:
						continue
					}
				}
				initLogf("syslog sink read failed: %v", err)
				return
			}
			msg := sanitizeSyslogMessage(string(buf[:n]))
			if msg != "" {
				initLogf("syslog: %s", msg)
			}
		}
	}()
	return nil
}

func sanitizeSyslogMessage(msg string) string {
	msg = strings.Trim(msg, "\x00\r\n\t ")
	msg = strings.ReplaceAll(msg, "\n", `\n`)
	msg = strings.ReplaceAll(msg, "\r", `\r`)
	if len(msg) > 512 {
		msg = msg[:512] + "...<truncated>"
	}
	return msg
}

func startOptionalNVIDIAFabricManager(ctx context.Context) {
	if !hasNVIDIANVSwitch() {
		initLogf("NVIDIA Fabric Manager skipped: no NVIDIA NVSwitch PCI device")
		return
	}
	runOptional(ctx, "/usr/bin/nvidia-fabricmanager-start.sh", "--mode", "precheck")
	runOptional(ctx, "/usr/bin/nvidia-fabricmanager-start.sh", "--mode", "start")
}

func waitForNVIDIANVML(ctx context.Context, timeout time.Duration) error {
	if _, err := os.Stat("/usr/bin/nvidia-smi"); err != nil {
		return nil
	}
	deadline := time.Now().Add(timeout)
	var lastErr error
	for {
		cmdCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		cmd := commandFor(cmdCtx, "", "/usr/bin/nvidia-smi", "-L")
		cmd.Env = childEnv()
		if nvidiaRMTraceEnabled() {
			cmd.Env = withNVIDIARMTraceEnv(cmd.Env)
		}
		output, err := cmd.CombinedOutput()
		cancel()
		trimmed := strings.TrimSpace(string(output))
		if err == nil && strings.Contains(trimmed, "NVIDIA") {
			initLogf("NVIDIA NVML ready: %s", firstLine(trimmed))
			return nil
		}
		if err != nil {
			lastErr = fmt.Errorf("nvidia-smi -L: %w: %s", err, trimmed)
		} else {
			lastErr = fmt.Errorf("nvidia-smi -L returned no NVIDIA devices: %s", trimmed)
		}
		if time.Now().After(deadline) {
			return lastErr
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}

func nvidiaRMTraceEnabled() bool {
	if !bootDebugEnabled() {
		return false
	}
	if _, err := os.Stat(nvidiaRMTraceLibrary); err != nil {
		return false
	}
	return true
}

func withNVIDIARMTraceEnv(env []string) []string {
	out := filterEnvKeys(env, "LD_PRELOAD", nvidiaRMTraceLogEnv)
	out = append(out, "LD_PRELOAD="+nvidiaRMTraceLibrary)
	out = append(out, nvidiaRMTraceLogEnv+"="+nvidiaRMTraceLog)
	return out
}

func filterEnvKeys(env []string, keys ...string) []string {
	if len(keys) == 0 {
		return append([]string(nil), env...)
	}
	drop := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		drop[key] = struct{}{}
	}
	out := make([]string, 0, len(env))
	for _, entry := range env {
		key, _, ok := strings.Cut(entry, "=")
		if !ok {
			out = append(out, entry)
			continue
		}
		if _, found := drop[key]; found {
			continue
		}
		out = append(out, entry)
	}
	return out
}

func logNVIDIARMTraceLog(stage string) {
	if !nvidiaRMTraceEnabled() {
		return
	}
	logReadableFile("NVIDIA RM trace "+stage, nvidiaRMTraceLog, nil)
}

func firstLine(value string) string {
	line, _, _ := strings.Cut(value, "\n")
	return line
}

func nvidiaDeviceMinors() ([]int, error) {
	entries, err := os.ReadDir(nvidiaGPUsDir)
	if err != nil {
		return nil, err
	}
	var minors []int
	var errs []error
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		minor, err := nvidiaDeviceMinor(filepath.Join(nvidiaGPUsDir, entry.Name(), "information"))
		if err != nil {
			errs = append(errs, err)
			continue
		}
		minors = append(minors, minor)
	}
	sort.Ints(minors)
	return uniqueInts(minors), errors.Join(errs...)
}

func nvidiaDeviceMinor(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok || strings.TrimSpace(key) != "Device Minor" {
			continue
		}
		minor, err := strconv.Atoi(strings.TrimSpace(value))
		if err != nil || minor < 0 {
			return 0, fmt.Errorf("invalid Device Minor in %s: %q", path, strings.TrimSpace(value))
		}
		return minor, nil
	}
	return 0, fmt.Errorf("missing Device Minor in %s", path)
}

func nvidiaCapabilityFiles() ([]string, error) {
	capabilities, err := nvidiaCapabilityDevices()
	if err != nil {
		return nil, err
	}
	var paths []string
	for _, capability := range capabilities {
		paths = append(paths, capability.path)
	}
	return paths, nil
}

type nvidiaCapabilityDevice struct {
	path  string
	minor int
	mode  os.FileMode
}

func nvidiaCapabilityDevices() ([]nvidiaCapabilityDevice, error) {
	var capabilities []nvidiaCapabilityDevice
	err := filepath.WalkDir(nvidiaCapabilitiesDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return filepath.SkipDir
			}
			return err
		}
		if d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil || !info.Mode().IsRegular() {
			return nil
		}
		capability, ok, err := parseNVIDIACapabilityDevice(path)
		if err != nil {
			return err
		}
		if ok && allowedNVIDIACapabilityPath(path) {
			capabilities = append(capabilities, capability)
		}
		return nil
	})
	if errors.Is(err, filepath.SkipDir) {
		err = nil
	}
	sort.Slice(capabilities, func(i, j int) bool {
		return capabilities[i].path < capabilities[j].path
	})
	return capabilities, err
}

func allowedNVIDIACapabilityPath(path string) bool {
	rel, err := filepath.Rel(nvidiaCapabilitiesDir, path)
	if err != nil {
		return false
	}
	switch filepath.ToSlash(rel) {
	case "mig/config", "mig/monitor":
		return true
	default:
		return false
	}
}

func parseNVIDIACapabilityDevice(path string) (nvidiaCapabilityDevice, bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nvidiaCapabilityDevice{}, false, err
	}
	attrs := parseColonAttrs(string(data))
	minorValue, ok := attrs["DeviceFileMinor"]
	if !ok {
		return nvidiaCapabilityDevice{}, false, nil
	}
	minor, err := strconv.Atoi(minorValue)
	if err != nil || minor < 0 {
		return nvidiaCapabilityDevice{}, false, fmt.Errorf("invalid DeviceFileMinor in %s: %q", path, minorValue)
	}
	mode := os.FileMode(0600)
	if modeValue, ok := attrs["DeviceFileMode"]; ok {
		parsed, err := strconv.ParseInt(modeValue, 0, 32)
		if err != nil || parsed < 0 {
			return nvidiaCapabilityDevice{}, false, fmt.Errorf("invalid DeviceFileMode in %s: %q", path, modeValue)
		}
		mode = os.FileMode(parsed) & 0777
	}
	return nvidiaCapabilityDevice{path: path, minor: minor, mode: mode}, true, nil
}

func ensureNVIDIADeviceNodes() error {
	majors, err := charDeviceMajors(procDevicesPath)
	if err != nil {
		return err
	}
	var errs []error

	if frontend, ok := firstMajor(majors, "nvidia-frontend", "nvidia"); ok {
		errs = append(errs, ensureNVIDIACharNode(filepath.Join(devRootDir, "nvidiactl"), frontend, nvidiaCtlMinor, 0666))
		errs = append(errs, ensureNVIDIACharNode(filepath.Join(devRootDir, "nvidia-modeset"), frontend, nvidiaModesetMinor, 0666))
		minors, err := nvidiaDeviceMinors()
		if err != nil {
			errs = append(errs, fmt.Errorf("discover GPU minors: %w", err))
		}
		for _, minor := range minors {
			errs = append(errs, ensureNVIDIACharNode(filepath.Join(devRootDir, fmt.Sprintf("nvidia%d", minor)), frontend, minor, 0666))
		}
	} else {
		errs = append(errs, errors.New("missing nvidia-frontend character major"))
	}

	if uvm, ok := firstMajor(majors, "nvidia-uvm"); ok {
		errs = append(errs, ensureNVIDIACharNode(filepath.Join(devRootDir, "nvidia-uvm"), uvm, nvidiaUVMMinor, 0666))
		errs = append(errs, ensureNVIDIACharNode(filepath.Join(devRootDir, "nvidia-uvm-tools"), uvm, nvidiaUVMToolsMinor, 0666))
	}

	if caps, ok := firstMajor(majors, "nvidia-caps"); ok {
		capabilities, err := nvidiaCapabilityDevices()
		if err != nil {
			errs = append(errs, fmt.Errorf("discover capability devices: %w", err))
		}
		for _, capability := range capabilities {
			path := filepath.Join(devRootDir, "nvidia-caps", fmt.Sprintf("nvidia-cap%d", capability.minor))
			errs = append(errs, ensureNVIDIACharNode(path, caps, capability.minor, capability.mode))
		}
	}

	return errors.Join(errs...)
}

func nvidiaPCIDevices() ([]string, error) {
	entries, err := os.ReadDir(pciDevicesDir)
	if err != nil {
		return nil, err
	}
	var devices []string
	for _, entry := range entries {
		vendor, err := os.ReadFile(filepath.Join(pciDevicesDir, entry.Name(), "vendor"))
		if err != nil || strings.TrimSpace(string(vendor)) != "0x10de" {
			continue
		}
		devices = append(devices, entry.Name())
	}
	sort.Strings(devices)
	return devices, nil
}

func isNVIDIAGPUClass(class string) bool {
	switch strings.TrimSpace(class) {
	case pciClassVGAController, pciClass3DController:
		return true
	default:
		return false
	}
}

// holdNVIDIAPCIEnableReference pins the PCI enable refcount of every NVIDIA
// GPU-class device by writing sysfs "enable" before the driver probes.
// Empirical B300 full-CC bring-up workaround: without the held reference the
// device could be disabled between the staged probe steps, failing the first
// RM open. The tinfoil-nvidia-skip-pci-enable-hold cmdline flag exists only
// to A/B this under tinfoil-debug and should be removed once confidence is
// established.
func holdNVIDIAPCIEnableReference() error {
	devices, err := nvidiaPCIDevices()
	if err != nil {
		return err
	}
	var errs []error
	for _, device := range devices {
		base := filepath.Join(pciDevicesDir, device)
		class, err := os.ReadFile(filepath.Join(base, "class"))
		if err != nil {
			errs = append(errs, fmt.Errorf("%s class: %w", device, err))
			continue
		}
		if !isNVIDIAGPUClass(string(class)) {
			continue
		}
		enablePath := filepath.Join(base, "enable")
		before := readTrimmed(enablePath)
		if err := os.WriteFile(enablePath, []byte("1\n"), 0644); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", enablePath, err))
			continue
		}
		after := readTrimmed(enablePath)
		initLogf("held NVIDIA PCI %s enable reference before driver probe: %s -> %s", device, before, after)
	}
	return errors.Join(errs...)
}

func enableNVIDIARuntimePowerManagement() error {
	devices, err := nvidiaPCIDevices()
	if err != nil {
		return err
	}
	var errs []error
	for _, device := range devices {
		base := filepath.Join(pciDevicesDir, device)
		class, err := os.ReadFile(filepath.Join(base, "class"))
		if err != nil {
			errs = append(errs, fmt.Errorf("%s class: %w", device, err))
			continue
		}
		if !isNVIDIAGPUClass(string(class)) {
			continue
		}
		control := filepath.Join(base, "power", "control")
		if err := os.WriteFile(control, []byte("auto\n"), 0644); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				initLogf("NVIDIA PCI %s has no runtime power control", device)
				continue
			}
			errs = append(errs, fmt.Errorf("%s: %w", control, err))
			continue
		}
		initLogf("set NVIDIA PCI %s runtime power control to auto", device)
	}
	return errors.Join(errs...)
}

func cmdlineHasField(field string) bool {
	data, err := os.ReadFile(procCmdlinePath)
	if err != nil {
		return false
	}
	for _, got := range strings.Fields(string(data)) {
		if got == field {
			return true
		}
	}
	return false
}

func bootDebugEnabled() bool {
	return cmdlineHasField("tinfoil-debug=on")
}

func nvidiaPCIEnableHoldDisabled() bool {
	return bootDebugEnabled() && cmdlineHasField(nvidiaSkipPCIEnableHold)
}

func nvidiaPreRMOpenDebugShellEnabled() bool {
	return bootDebugEnabled() && cmdlineHasField(nvidiaPreRMOpenShell)
}

func maybeRunNVIDIAPreRMOpenDebugShell(ctx context.Context) {
	if !nvidiaPreRMOpenDebugShellEnabled() {
		return
	}
	if err := ctx.Err(); err != nil {
		initLogf("NVIDIA pre-RM-open debug shell skipped: context canceled: %v", err)
		return
	}
	initLogf("NVIDIA pre-RM-open debug shell enabled; starting /bin/sh on %s", consolePath)
	initLogf("collect pre-open evidence, run the first RM/NVML open manually, then exit shell to continue boot")
	if err := runConsoleShell("TINFOIL_NVIDIA_PRE_RM_OPEN_SHELL=1"); err != nil {
		initLogf("warning: NVIDIA pre-RM-open debug shell unavailable: %v", err)
	}
	initLogf("NVIDIA pre-RM-open debug shell exited; continuing NVIDIA bootstrap")
}

func runConsoleShell(extraEnv ...string) error {
	console, err := os.OpenFile(consolePath, os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("open %s: %w", consolePath, err)
	}
	defer console.Close()

	cmd := exec.Command("/bin/sh", "-i")
	cmd.Dir = "/"
	cmd.Env = append(childEnv(), extraEnv...)
	cmd.Stdin = console
	cmd.Stdout = console
	cmd.Stderr = console
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid:    true,
		Setctty:   true,
		Ctty:      0,
		Pdeathsig: syscall.SIGKILL,
	}
	return cmd.Run()
}

func tinfoilBootTimeout() time.Duration {
	if bootDebugEnabled() {
		return 0
	}
	return bootTimeout
}

func bootContext(parent context.Context) (context.Context, context.CancelFunc) {
	if bootDebugEnabled() {
		return parent, func() {}
	}
	return context.WithTimeout(parent, bootTimeout)
}

func logRuntimeEnvironmentDiagnostics(stage string) {
	initLogf("runtime environment diagnostics %s begin", stage)
	logReadableFile("runtime limits "+stage, "/proc/self/limits", nil)
	logReadableFile("runtime mounts "+stage, "/proc/self/mountinfo", runtimeMountLineInteresting)
	logReadableFile("runtime /dev/shm stat "+stage, "/proc/self/mounts", func(line string) bool {
		return strings.Contains(line, " /dev/shm ") || strings.Contains(line, " /run/shm ")
	})
	initLogf("runtime environment diagnostics %s end", stage)
}

func runtimeMountLineInteresting(line string) bool {
	for _, needle := range []string{
		" /dev/shm ",
		" /run ",
		" " + boot.RamdiskDir + " ",
		" /tmp ",
		" /var/tmp ",
		" /dev/pts ",
		" /dev/mqueue ",
		" /dev/hugepages ",
		" /sys/fs/cgroup ",
	} {
		if strings.Contains(line, needle) {
			return true
		}
	}
	return false
}

func logNVIDIAPersistencedProcessDiagnostics(stage string) {
	pidData, err := os.ReadFile(nvidiaPersistencedPIDPath)
	if err != nil {
		initLogf("NVIDIA persistenced process diagnostics %s unavailable: %v", stage, err)
		return
	}
	pid := strings.TrimSpace(string(pidData))
	if _, err := strconv.Atoi(pid); err != nil {
		initLogf("NVIDIA persistenced process diagnostics %s invalid pid %q: %v", stage, pid, err)
		return
	}
	base := filepath.Join("/proc", pid)
	initLogf("NVIDIA persistenced process diagnostics %s pid=%s begin", stage, pid)
	logReadableFile("NVIDIA persistenced limits "+stage, filepath.Join(base, "limits"), nil)
	logReadableFile("NVIDIA persistenced status "+stage, filepath.Join(base, "status"), func(line string) bool {
		for _, prefix := range []string{
			"Name:",
			"State:",
			"Uid:",
			"Gid:",
			"Groups:",
			"VmLck:",
			"Cap",
			"NoNewPrivs:",
			"Seccomp:",
			"Cpus_allowed_list:",
			"Mems_allowed_list:",
		} {
			if strings.HasPrefix(line, prefix) {
				return true
			}
		}
		return false
	})
	logReadableFile("NVIDIA persistenced cgroup "+stage, filepath.Join(base, "cgroup"), nil)
	initLogf("NVIDIA persistenced process diagnostics %s pid=%s end", stage, pid)
}

func logNVIDIADebugDiagnostics(ctx context.Context) {
	initLogf("NVIDIA debug diagnostics begin")
	logRuntimeEnvironmentDiagnostics("nvidia-debug")
	logNVIDIAPersistencedProcessDiagnostics("nvidia-debug")
	logNVIDIAPCIState()
	logReadableFile("NVIDIA modules", "/proc/modules", func(line string) bool {
		return strings.HasPrefix(line, "nvidia") || strings.HasPrefix(line, "video ")
	})
	logReadableFile("NVIDIA driver params", "/proc/driver/nvidia/params", nil)
	logReadableGlob("NVIDIA GPU information", filepath.Join(nvidiaGPUsDir, "*", "information"))
	logReadableGlob("NVIDIA GPU power", filepath.Join(nvidiaGPUsDir, "*", "power"))
	logReadableGlob("NVIDIA GPU registry", filepath.Join(nvidiaGPUsDir, "*", "registry"))
	logReadableGlob("NVIDIA capability", filepath.Join(nvidiaCapabilitiesDir, "*", "*", "*"))
	logNVIDIADeviceStats()
	logKernelRingFiltered("kernel GPU diagnostics", func(line string) bool {
		lower := strings.ToLower(line)
		return strings.Contains(lower, "nvidia") ||
			strings.Contains(lower, "nvrm") ||
			strings.Contains(lower, "gsp") ||
			strings.Contains(lower, "gpu firmware") ||
			strings.Contains(lower, "wmi") ||
			strings.Contains(lower, "unknown symbol") ||
			strings.Contains(lower, "module verification") ||
			strings.Contains(lower, "xid") ||
			strings.Contains(lower, "nvidia_modeset") ||
			strings.Contains(lower, "nvidia-modeset")
	})
	runOptional(ctx, "/usr/bin/nvidia-smi", "-L")
	initLogf("NVIDIA debug diagnostics end")
}

func logNVIDIAPCIState() {
	devices, err := nvidiaPCIDevices()
	if err != nil {
		initLogf("NVIDIA PCI state unavailable: %v", err)
		return
	}
	for _, device := range devices {
		base := filepath.Join(pciDevicesDir, device)
		vendor := readTrimmed(filepath.Join(base, "vendor"))
		devID := readTrimmed(filepath.Join(base, "device"))
		class := readTrimmed(filepath.Join(base, "class"))
		powerControl := readTrimmed(filepath.Join(base, "power", "control"))
		runtimeStatus := readTrimmed(filepath.Join(base, "power", "runtime_status"))
		numaNode := readTrimmed(filepath.Join(base, "numa_node"))
		enable := readTrimmed(filepath.Join(base, "enable"))
		irq := readTrimmed(filepath.Join(base, "irq"))
		driver := readSymlinkTarget(filepath.Join(base, "driver"))
		driverModule := readSymlinkTarget(filepath.Join(base, "driver", "module"))
		initLogf("NVIDIA PCI %s vendor=%s device=%s class=%s power/control=%s runtime_status=%s numa_node=%s enable=%s irq=%s driver=%s driver_module=%s",
			device, vendor, devID, class, powerControl, runtimeStatus, numaNode, enable, irq, driver, driverModule)
		for _, rel := range []string{
			"modalias",
			"uevent",
			"msi_bus",
			"local_cpulist",
			"local_cpus",
			"current_link_speed",
			"current_link_width",
			"max_link_speed",
			"max_link_width",
			"d3cold_allowed",
			"reset_method",
			filepath.Join("power", "runtime_usage"),
			filepath.Join("power", "runtime_active_time"),
			filepath.Join("power", "runtime_suspended_time"),
		} {
			logReadableFile("NVIDIA PCI "+device+" "+filepath.ToSlash(rel), filepath.Join(base, rel), nil)
		}
		logDirectoryEntries("NVIDIA PCI "+device+" msi_irqs", filepath.Join(base, "msi_irqs"))
		logReadableFile("NVIDIA PCI "+device+" resource", filepath.Join(base, "resource"), nil)
		logNVIDIAPCIConfig(device, base)
	}
	logReadableFile("NVIDIA interrupts", "/proc/interrupts", func(line string) bool {
		lower := strings.ToLower(line)
		return strings.Contains(lower, "nvidia") || strings.Contains(lower, "01:00")
	})
}

func logNVIDIAPCIConfig(device, base string) {
	file, err := os.Open(filepath.Join(base, "config"))
	if err != nil {
		initLogf("NVIDIA PCI %s config unavailable: %v", device, err)
		return
	}
	defer file.Close()

	buf := make([]byte, pciConfigSnapshotLen)
	n, err := file.ReadAt(buf, 0)
	if err != nil && !errors.Is(err, io.EOF) {
		initLogf("NVIDIA PCI %s config read failed: %v", device, err)
		return
	}
	if n == 0 {
		initLogf("NVIDIA PCI %s config empty", device)
		return
	}
	initLogf("NVIDIA PCI %s config[0:%d]=%s", device, n, hex.EncodeToString(buf[:n]))
	if n >= 8 {
		command := binary.LittleEndian.Uint16(buf[pciCommandOffset : pciCommandOffset+2])
		status := binary.LittleEndian.Uint16(buf[pciCommandOffset+2 : pciCommandOffset+4])
		initLogf("NVIDIA PCI %s command=0x%04x status=0x%04x intx_disabled=%t",
			device, command, status, command&pciCommandINTxDisable != 0)
	}
	for _, capability := range parsePCICapabilities(buf[:n]) {
		initLogf("NVIDIA PCI %s %s", device, describePCICapability(buf[:n], capability))
	}
}

type pciCapability struct {
	offset int
	id     byte
	next   byte
}

func parsePCICapabilities(config []byte) []pciCapability {
	if len(config) <= pciCapabilityPtrType0 {
		return nil
	}
	if len(config) < pciStatusOffset+2 {
		return nil
	}
	status := binary.LittleEndian.Uint16(config[pciStatusOffset : pciStatusOffset+2])
	if status&pciStatusCapabilities == 0 {
		return nil
	}
	headerType := config[pciHeaderTypeOffset] & pciHeaderTypeMask
	if headerType != 0 {
		return nil
	}

	ptr := int(config[pciCapabilityPtrType0] &^ pciCapPtrAlignMask)
	seen := map[int]struct{}{}
	var capabilities []pciCapability
	for i := 0; i < maxPCICapabilities && ptr >= pciStdHeaderSize && ptr+1 < len(config); i++ {
		if _, ok := seen[ptr]; ok {
			break
		}
		seen[ptr] = struct{}{}
		id := config[ptr]
		next := config[ptr+1]
		if id == 0x00 || id == 0xff {
			break
		}
		capabilities = append(capabilities, pciCapability{offset: ptr, id: id, next: next})
		if next == 0 {
			break
		}
		ptr = int(next &^ pciCapPtrAlignMask)
	}
	return capabilities
}

func describePCICapability(config []byte, capability pciCapability) string {
	end := capability.offset + 16
	if end > len(config) {
		end = len(config)
	}
	raw := ""
	if capability.offset < end {
		raw = hex.EncodeToString(config[capability.offset:end])
	}
	base := fmt.Sprintf("capability id=0x%02x(%s) offset=0x%02x next=0x%02x raw=%s",
		capability.id, pciCapabilityName(capability.id), capability.offset, capability.next, raw)

	if capability.offset+4 > len(config) {
		return base
	}
	control := binary.LittleEndian.Uint16(config[capability.offset+2 : capability.offset+4])
	switch capability.id {
	case pciCapabilityMSI:
		mmc := (control >> 1) & 0x7
		mme := (control >> 4) & 0x7
		return fmt.Sprintf("%s msi_enable=%t multiple_message_capable=%d multiple_message_enable=%d address64=%t per_vector_mask=%t",
			base, control&0x0001 != 0, mmc, mme, control&0x0080 != 0, control&0x0100 != 0)
	case pciCapabilityMSIX:
		tableSize := (control & 0x07ff) + 1
		return fmt.Sprintf("%s msix_enable=%t function_mask=%t table_size=%d",
			base, control&msixCtrlEnable != 0, control&msixCtrlFuncMask != 0, tableSize)
	default:
		return base
	}
}

func pciCapabilityName(id byte) string {
	switch id {
	case pciCapabilityMSI:
		return "MSI"
	case pciCapabilityMSIX:
		return "MSI-X"
	default:
		return "unknown"
	}
}

func readSymlinkTarget(path string) string {
	target, err := os.Readlink(path)
	if err != nil {
		return "unavailable:" + err.Error()
	}
	return target
}

func logDirectoryEntries(label, path string) {
	entries, err := os.ReadDir(path)
	if err != nil {
		initLogf("%s unavailable: %v", label, err)
		return
	}
	if len(entries) == 0 {
		initLogf("%s: empty", label)
		return
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name() < entries[j].Name()
	})
	for _, entry := range entries {
		name := entry.Name()
		initLogf("%s entry: %s", label, name)
		if !entry.IsDir() {
			logReadableFile(label+" "+name, filepath.Join(path, name), nil)
		}
	}
}

func logReadableGlob(label, pattern string) {
	paths, err := filepath.Glob(pattern)
	if err != nil {
		initLogf("%s glob %s failed: %v", label, pattern, err)
		return
	}
	sort.Strings(paths)
	for _, path := range paths {
		logReadableFile(label+" "+path, path, nil)
	}
}

func logReadableFile(label, path string, keep func(string) bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		initLogf("%s unavailable: %v", label, err)
		return
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}
		if keep != nil && !keep(line) {
			continue
		}
		initLogf("%s: %s", label, line)
	}
}

func logKernelRingFiltered(label string, keep func(string) bool) {
	size, err := unix.Klogctl(unix.SYSLOG_ACTION_SIZE_BUFFER, nil)
	if err != nil {
		initLogf("%s unavailable: %v", label, err)
		return
	}
	if size < 4096 {
		size = 4096
	}
	if size > 1<<20 {
		size = 1 << 20
	}
	buf := make([]byte, size)
	n, err := unix.Klogctl(unix.SYSLOG_ACTION_READ_ALL, buf)
	if err != nil {
		initLogf("%s read failed: %v", label, err)
		return
	}
	lines := strings.Split(strings.TrimRight(string(buf[:n]), "\n"), "\n")
	logged := 0
	for _, line := range lines {
		if line == "" {
			continue
		}
		if keep != nil && !keep(line) {
			continue
		}
		if logged >= 120 {
			initLogf("%s: truncated after %d matching lines", label, logged)
			return
		}
		initLogf("%s: %s", label, line)
		logged++
	}
}

func logNVIDIADeviceStats() {
	patterns := []string{
		filepath.Join(devRootDir, "nvidia*"),
		filepath.Join(devRootDir, "nvidia-caps", "nvidia-cap*"),
		filepath.Join(devRootDir, "char", "*"),
		filepath.Join(devRootDir, "dri", "*"),
	}
	for _, pattern := range patterns {
		paths, err := filepath.Glob(pattern)
		if err != nil {
			initLogf("NVIDIA device stat glob %s failed: %v", pattern, err)
			continue
		}
		sort.Strings(paths)
		for _, path := range paths {
			info, err := os.Lstat(path)
			if err != nil {
				initLogf("NVIDIA device stat %s unavailable: %v", path, err)
				continue
			}
			if info.Mode()&os.ModeSymlink != 0 {
				target, err := os.Readlink(path)
				if err != nil {
					initLogf("NVIDIA device symlink %s unreadable: %v", path, err)
					continue
				}
				initLogf("NVIDIA device symlink %s -> %s", path, target)
				continue
			}
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok {
				initLogf("NVIDIA device stat %s mode=%s", path, info.Mode())
				continue
			}
			initLogf("NVIDIA device stat %s mode=%#o uid=%d gid=%d major=%d minor=%d",
				path, info.Mode().Perm(), stat.Uid, stat.Gid, unix.Major(uint64(stat.Rdev)), unix.Minor(uint64(stat.Rdev)))
		}
	}
}

func readTrimmed(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return "unavailable:" + err.Error()
	}
	return strings.TrimSpace(string(data))
}

func charDeviceMajors(path string) (map[string]int, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	majors := map[string]int{}
	inCharDevices := false
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		switch line {
		case "Character devices:":
			inCharDevices = true
			continue
		case "Block devices:":
			inCharDevices = false
			continue
		}
		if !inCharDevices || line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		major, err := strconv.Atoi(fields[0])
		if err != nil || major < 0 {
			continue
		}
		majors[fields[1]] = major
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return majors, nil
}

func firstMajor(majors map[string]int, names ...string) (int, bool) {
	for _, name := range names {
		major, ok := majors[name]
		if ok {
			return major, true
		}
	}
	return 0, false
}

func ensureCharNode(path string, major, minor int, mode os.FileMode) error {
	if major < 0 || minor < 0 {
		return fmt.Errorf("invalid char device %s major=%d minor=%d", path, major, minor)
	}
	dev := int(unix.Mkdev(uint32(major), uint32(minor)))
	info, err := os.Lstat(path)
	if err == nil {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || info.Mode()&os.ModeCharDevice == 0 {
			return fmt.Errorf("%s exists but is not a character device", path)
		}
		if int(unix.Major(uint64(stat.Rdev))) != major || int(unix.Minor(uint64(stat.Rdev))) != minor {
			return fmt.Errorf("%s has unexpected major:minor %d:%d", path, unix.Major(uint64(stat.Rdev)), unix.Minor(uint64(stat.Rdev)))
		}
		if err := os.Chmod(path, mode.Perm()); err != nil {
			return fmt.Errorf("chmod %s: %w", path, err)
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	if err := unix.Mknod(path, uint32(unix.S_IFCHR|mode.Perm()), dev); err != nil {
		return fmt.Errorf("mknod %s %d:%d: %w", path, major, minor, err)
	}
	if err := os.Chmod(path, mode.Perm()); err != nil {
		return fmt.Errorf("chmod %s: %w", path, err)
	}
	initLogf("created NVIDIA device node %s major=%d minor=%d", path, major, minor)
	return nil
}

func ensureNVIDIACharNode(path string, major, minor int, mode os.FileMode) error {
	if err := ensureCharNode(path, major, minor, mode); err != nil {
		return err
	}
	return ensureDevCharSymlink(path, major, minor)
}

func ensureDevCharSymlink(path string, major, minor int) error {
	if major < 0 || minor < 0 {
		return fmt.Errorf("invalid /dev/char symlink for %s major=%d minor=%d", path, major, minor)
	}
	charDir := filepath.Join(devRootDir, "char")
	linkPath := filepath.Join(charDir, fmt.Sprintf("%d:%d", major, minor))
	target, err := filepath.Rel(charDir, path)
	if err != nil {
		return fmt.Errorf("relative symlink target for %s: %w", path, err)
	}
	if err := os.MkdirAll(charDir, 0755); err != nil {
		return err
	}
	info, err := os.Lstat(linkPath)
	if err == nil {
		if info.Mode()&os.ModeSymlink == 0 {
			return fmt.Errorf("%s exists but is not a symlink", linkPath)
		}
		current, err := os.Readlink(linkPath)
		if err != nil {
			return fmt.Errorf("readlink %s: %w", linkPath, err)
		}
		if current == target {
			return nil
		}
		if err := os.Remove(linkPath); err != nil {
			return fmt.Errorf("remove stale %s: %w", linkPath, err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Symlink(target, linkPath); err != nil {
		return fmt.Errorf("symlink %s -> %s: %w", linkPath, target, err)
	}
	initLogf("created NVIDIA /dev/char symlink %s -> %s", linkPath, target)
	return nil
}

func parseColonAttrs(data string) map[string]string {
	attrs := map[string]string{}
	for _, line := range strings.Split(data, "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		attrs[strings.TrimSpace(key)] = strings.TrimSpace(value)
	}
	return attrs
}

func hasNVIDIAPCIDevice() bool {
	entries, err := os.ReadDir(pciDevicesDir)
	if err != nil {
		initLogf("NVIDIA services skipped: reading %s: %v", pciDevicesDir, err)
		return false
	}
	for _, entry := range entries {
		vendor, err := os.ReadFile(filepath.Join(pciDevicesDir, entry.Name(), "vendor"))
		if err != nil {
			continue
		}
		if strings.TrimSpace(string(vendor)) == "0x10de" {
			return true
		}
	}
	return false
}

func hasNVIDIANVSwitch() bool {
	entries, err := os.ReadDir(pciDevicesDir)
	if err != nil {
		initLogf("NVIDIA Fabric Manager skipped: reading %s: %v", pciDevicesDir, err)
		return false
	}
	for _, entry := range entries {
		base := filepath.Join(pciDevicesDir, entry.Name())
		vendor, err := os.ReadFile(filepath.Join(base, "vendor"))
		if err != nil || strings.TrimSpace(string(vendor)) != "0x10de" {
			continue
		}
		class, err := os.ReadFile(filepath.Join(base, "class"))
		if err != nil {
			continue
		}
		if strings.TrimSpace(string(class)) == "0x068000" {
			return true
		}
	}
	return false
}

func uniqueInts(values []int) []int {
	if len(values) == 0 {
		return nil
	}
	out := values[:0]
	for _, value := range values {
		if len(out) == 0 || out[len(out)-1] != value {
			out = append(out, value)
		}
	}
	return out
}

func uniqueStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	out := values[:0]
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func runOptional(ctx context.Context, path string, args ...string) {
	if _, err := os.Stat(path); err != nil {
		return
	}
	if err := runOneShot(ctx, optionalCommandTimeout, path, args...); err != nil {
		initLogf("optional command failed: %s %s: %v", path, strings.Join(args, " "), err)
	}
}

func runOneShot(ctx context.Context, timeout time.Duration, path string, args ...string) error {
	return runOneShotHardened(ctx, timeout, "", path, args...)
}

func runOneShotHardened(ctx context.Context, timeout time.Duration, harden, path string, args ...string) error {
	return runOneShotHardenedEnv(ctx, timeout, harden, childEnv(), path, args...)
}

func runOneShotEnv(ctx context.Context, timeout time.Duration, env []string, path string, args ...string) error {
	return runOneShotHardenedEnv(ctx, timeout, "", env, path, args...)
}

func runOneShotHardenedEnv(ctx context.Context, timeout time.Duration, harden string, env []string, path string, args ...string) error {
	cmdCtx := ctx
	var cancel context.CancelFunc
	if timeout > 0 {
		cmdCtx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	cmd := commandFor(cmdCtx, harden, path, args...)
	cmd.Env = env
	cmd.Stdout = prefixedWriter(filepath.Base(path))
	cmd.Stderr = prefixedWriter(filepath.Base(path))
	initLogf("running %s %s", path, strings.Join(args, " "))
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %s: %w", path, strings.Join(args, " "), err)
	}
	return nil
}

func startManaged(ctx context.Context, proc *managedProcess) (*managedProcess, error) {
	if _, err := os.Stat(proc.path); err != nil {
		if proc.required {
			return nil, err
		}
		initLogf("%s skipped: %v", proc.name, err)
		return proc, nil
	}
	if err := startProcess(proc); err != nil {
		if proc.required {
			return nil, err
		}
		initLogf("warning: starting %s: %v", proc.name, err)
		return proc, nil
	}
	go monitorProcess(ctx, proc)
	return proc, nil
}

func startProcess(proc *managedProcess) error {
	cmd := commandFor(context.Background(), proc.harden, proc.path, proc.args...)
	cmd.Env = childEnv()
	cmd.Stdout = prefixedWriter(proc.name)
	cmd.Stderr = prefixedWriter(proc.name)
	if err := cmd.Start(); err != nil {
		return err
	}
	proc.cmd = cmd
	initLogf("started %s pid=%d", proc.name, cmd.Process.Pid)
	return nil
}

func monitorProcess(ctx context.Context, proc *managedProcess) {
	for {
		err := proc.cmd.Wait()
		if ctx.Err() != nil {
			return
		}
		if err == nil && !proc.restart {
			initLogf("%s exited", proc.name)
			return
		}
		initLogf("%s exited: %v", proc.name, err)
		if !proc.restart {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
		if err := startProcess(proc); err != nil {
			initLogf("restart %s failed: %v", proc.name, err)
			if proc.required {
				for {
					time.Sleep(time.Minute)
				}
			}
		}
	}
}

func commandFor(ctx context.Context, harden, path string, args ...string) *exec.Cmd {
	if harden == "" {
		return exec.CommandContext(ctx, path, args...)
	}
	wrapperArgs := append([]string{"--exec-service", harden, "--", path}, args...)
	return exec.CommandContext(ctx, selfExecPath, wrapperArgs...)
}

func execService(args []string) error {
	if len(args) < 3 {
		return errors.New("usage: --exec-service <policy> -- <path> [args...]")
	}
	policyName := args[0]
	if args[1] != "--" {
		return errors.New("missing -- after policy")
	}
	target := args[2]
	targetArgs := args[2:]
	policy, ok := serviceHardeningPolicy[policyName]
	if !ok {
		return fmt.Errorf("unknown service hardening policy %q", policyName)
	}
	if len(policy.boundCaps) > 0 || policy.boundCaps != nil {
		if err := applyCapabilityBounding(policy.boundCaps); err != nil {
			return fmt.Errorf("apply capability bounding: %w", err)
		}
	}
	if policy.noNewPrivileges {
		if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
			return fmt.Errorf("set no_new_privs: %w", err)
		}
	}
	if err := syscall.Exec(target, targetArgs, childEnv()); err != nil {
		return fmt.Errorf("exec %s: %w", target, err)
	}
	return nil
}

func applyCapabilityBounding(caps []int) error {
	allowed := make(map[int]struct{}, len(caps))
	for _, cap := range caps {
		allowed[cap] = struct{}{}
	}
	last := capLast()
	for cap := 0; cap <= last; cap++ {
		if _, ok := allowed[cap]; ok {
			continue
		}
		err := unix.Prctl(unix.PR_CAPBSET_DROP, uintptr(cap), 0, 0, 0)
		if err != nil && !errors.Is(err, unix.EINVAL) {
			return fmt.Errorf("drop cap %d from bounding set: %w", cap, err)
		}
	}

	data := capabilityData(caps)
	header := unix.CapUserHeader{
		Version: unix.LINUX_CAPABILITY_VERSION_3,
		Pid:     0,
	}
	if err := unix.Capset(&header, &data[0]); err != nil {
		return fmt.Errorf("capset: %w", err)
	}
	return nil
}

func capabilityData(caps []int) [2]unix.CapUserData {
	var data [2]unix.CapUserData
	for _, cap := range caps {
		if cap < 0 {
			continue
		}
		index := cap / 32
		if index >= len(data) {
			continue
		}
		bit := uint32(1) << uint(cap%32)
		data[index].Effective |= bit
		data[index].Permitted |= bit
		data[index].Inheritable |= bit
	}
	return data
}

func capLast() int {
	raw, err := os.ReadFile("/proc/sys/kernel/cap_last_cap")
	if err != nil {
		return 63
	}
	value, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil || value < 0 || value > 1024 {
		return 63
	}
	return value
}

func stopProcess(proc *managedProcess) {
	if proc == nil || proc.cmd == nil || proc.cmd.Process == nil {
		return
	}
	_ = proc.cmd.Process.Signal(syscall.SIGTERM)
}

func waitForPath(ctx context.Context, path string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		if _, err := os.Stat(path); err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%s not present before timeout", path)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
}

func childEnv() []string {
	env := os.Environ()
	env = append(env, "PATH=/usr/sbin:/usr/bin:/sbin:/bin")
	env = append(env, tinfoilPID1Env+"="+tinfoilPID1EnvValue)
	env = append(env, "DOCKER_HOST=unix://"+dockerSocket)
	return env
}

func prefixedWriter(prefix string) io.Writer {
	return writerFunc(func(p []byte) (int, error) {
		for _, line := range strings.SplitAfter(string(p), "\n") {
			line = strings.TrimRight(line, "\n")
			if line == "" {
				continue
			}
			initLogf("%s: %s", prefix, line)
		}
		return len(p), nil
	})
}

type writerFunc func([]byte) (int, error)

func (fn writerFunc) Write(p []byte) (int, error) {
	return fn(p)
}

func initLogf(format string, args ...any) {
	message := fmt.Sprintf(format, args...)
	consoleMu.Lock()
	defer consoleMu.Unlock()
	log.Print("tinfoil-init: " + message)
	for _, path := range []string{"/dev/kmsg", "/dev/ttyS0", "/dev/console"} {
		file, err := os.OpenFile(path, os.O_WRONLY|syscall.O_NONBLOCK, 0)
		if err != nil {
			continue
		}
		if path == "/dev/kmsg" {
			_, _ = fmt.Fprintf(file, "<6>tinfoil-init: %s\n", message)
		} else {
			_, _ = fmt.Fprintf(file, "tinfoil-init: %s\n", message)
		}
		_ = file.Close()
	}
}
