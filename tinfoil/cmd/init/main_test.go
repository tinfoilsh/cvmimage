package main

import (
	"context"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestCommandForHardenedServiceUsesSelfExecWrapper(t *testing.T) {
	cmd := commandFor(context.Background(), shimName, "/usr/bin/tinfoil-shim", "--flag")

	want := []string{
		selfExecPath,
		"--exec-service",
		shimName,
		"--",
		"/usr/bin/tinfoil-shim",
		"--flag",
	}
	if !reflect.DeepEqual(cmd.Args, want) {
		t.Fatalf("Args = %#v, want %#v", cmd.Args, want)
	}
}

func TestCommandForUnhardenedServiceExecsTargetDirectly(t *testing.T) {
	cmd := commandFor(context.Background(), "", "/usr/bin/containerd", "--log-level=info")

	want := []string{"/usr/bin/containerd", "--log-level=info"}
	if !reflect.DeepEqual(cmd.Args, want) {
		t.Fatalf("Args = %#v, want %#v", cmd.Args, want)
	}
}

func TestCapabilityDataPacksLowAndHighCapabilities(t *testing.T) {
	data := capabilityData([]int{unix.CAP_NET_BIND_SERVICE, 33, -1, 65})

	low := uint32(1) << uint(unix.CAP_NET_BIND_SERVICE)
	high := uint32(1) << 1
	if data[0].Effective != low || data[0].Permitted != low || data[0].Inheritable != low {
		t.Fatalf("low capability data = %#v, want only bit %#x set", data[0], low)
	}
	if data[1].Effective != high || data[1].Permitted != high || data[1].Inheritable != high {
		t.Fatalf("high capability data = %#v, want only bit %#x set", data[1], high)
	}
}

func TestTinfoilOwnedPoliciesAreHardened(t *testing.T) {
	tests := map[string][]int{
		"tinfoil-boot":      nil,
		containerStatusName: {},
		egressName:          {unix.CAP_NET_ADMIN},
		shimName:            {unix.CAP_NET_BIND_SERVICE},
	}
	for name, caps := range tests {
		t.Run(name, func(t *testing.T) {
			policy, ok := serviceHardeningPolicy[name]
			if !ok {
				t.Fatalf("policy %q missing", name)
			}
			if !policy.noNewPrivileges {
				t.Fatalf("policy %q does not set no_new_privs", name)
			}
			if caps != nil && !reflect.DeepEqual(policy.boundCaps, caps) {
				t.Fatalf("policy %q caps = %#v, want %#v", name, policy.boundCaps, caps)
			}
		})
	}
}

func TestHasNVIDIAPCIDevice(t *testing.T) {
	old := pciDevicesDir
	t.Cleanup(func() { pciDevicesDir = old })

	dir := t.TempDir()
	pciDevicesDir = dir
	if hasNVIDIAPCIDevice() {
		t.Fatalf("expected no NVIDIA device in empty sysfs fixture")
	}

	device := filepath.Join(dir, "0000:bd:00.0")
	if err := os.MkdirAll(device, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(device, "vendor"), []byte("0x10de\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if !hasNVIDIAPCIDevice() {
		t.Fatalf("expected NVIDIA device to be detected")
	}
}

func TestHasNVIDIANVSwitchRequiresNVIDIASwitchClass(t *testing.T) {
	old := pciDevicesDir
	t.Cleanup(func() { pciDevicesDir = old })

	dir := t.TempDir()
	pciDevicesDir = dir
	gpu := filepath.Join(dir, "0000:01:00.0")
	nvswitch := filepath.Join(dir, "0000:02:00.0")
	other := filepath.Join(dir, "0000:03:00.0")
	for _, device := range []string{gpu, nvswitch, other} {
		if err := os.MkdirAll(device, 0755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(gpu, "vendor"), []byte("0x10de\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(gpu, "class"), []byte("0x030200\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(other, "vendor"), []byte("0x1af4\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(other, "class"), []byte("0x068000\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if hasNVIDIANVSwitch() {
		t.Fatalf("expected NVIDIA GPU and non-NVIDIA bridge not to trigger NVSwitch")
	}

	if err := os.WriteFile(filepath.Join(nvswitch, "vendor"), []byte("0x10de\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nvswitch, "class"), []byte("0x068000\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if !hasNVIDIANVSwitch() {
		t.Fatalf("expected NVIDIA bridge class to trigger NVSwitch")
	}
}

func TestFirstLine(t *testing.T) {
	if got := firstLine("GPU 0: NVIDIA B300\nextra"); got != "GPU 0: NVIDIA B300" {
		t.Fatalf("firstLine = %q", got)
	}
}

func TestReadSystemUptime(t *testing.T) {
	path := filepath.Join(t.TempDir(), "uptime")
	if err := os.WriteFile(path, []byte("17.000000 42.000000\n"), 0644); err != nil {
		t.Fatal(err)
	}
	got, err := readSystemUptime(path)
	if err != nil {
		t.Fatalf("readSystemUptime: %v", err)
	}
	if got != 17*time.Second {
		t.Fatalf("uptime = %s, want 17s", got)
	}

	if err := os.WriteFile(path, []byte("-1 0\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readSystemUptime(path); err == nil {
		t.Fatal("expected invalid negative uptime to fail")
	}
}

func TestLookupPasswdUser(t *testing.T) {
	old := passwdPath
	t.Cleanup(func() { passwdPath = old })

	path := filepath.Join(t.TempDir(), "passwd")
	passwdPath = path
	if err := os.WriteFile(path, []byte("root:x:0:0:root:/root:/bin/sh\nnvidia-persistenced:x:100:101:NVIDIA Persistence Daemon:/var/run/nvidia-persistenced/:/usr/sbin/nologin\n"), 0644); err != nil {
		t.Fatal(err)
	}

	uid, gid, err := lookupPasswdUser("nvidia-persistenced")
	if err != nil {
		t.Fatalf("lookupPasswdUser: %v", err)
	}
	if uid != 100 || gid != 101 {
		t.Fatalf("uid,gid = %d,%d, want 100,101", uid, gid)
	}
}

func TestPrepareNVIDIAPersistencedRuntime(t *testing.T) {
	oldRunDir := nvidiaPersistencedRunDir
	oldSocket := nvidiaPersistencedSocket
	oldPIDPath := nvidiaPersistencedPIDPath
	oldPasswd := passwdPath
	t.Cleanup(func() {
		nvidiaPersistencedRunDir = oldRunDir
		nvidiaPersistencedSocket = oldSocket
		nvidiaPersistencedPIDPath = oldPIDPath
		passwdPath = oldPasswd
	})

	dir := t.TempDir()
	nvidiaPersistencedRunDir = filepath.Join(dir, "run", "nvidia-persistenced")
	nvidiaPersistencedSocket = filepath.Join(nvidiaPersistencedRunDir, "socket")
	nvidiaPersistencedPIDPath = filepath.Join(nvidiaPersistencedRunDir, "nvidia-persistenced.pid")
	passwdPath = filepath.Join(dir, "passwd")
	if err := os.WriteFile(passwdPath, []byte("nvidia-persistenced:x:"+strconv.Itoa(os.Getuid())+":"+strconv.Itoa(os.Getgid())+":NVIDIA Persistence Daemon:/var/run/nvidia-persistenced/:/usr/sbin/nologin\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(nvidiaPersistencedRunDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(nvidiaPersistencedSocket, []byte("stale"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(nvidiaPersistencedPIDPath, []byte("123\n"), 0600); err != nil {
		t.Fatal(err)
	}

	if err := prepareNVIDIAPersistencedRuntime(); err != nil {
		t.Fatalf("prepareNVIDIAPersistencedRuntime: %v", err)
	}
	info, err := os.Stat(nvidiaPersistencedRunDir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0755 {
		t.Fatalf("mode = %v, want 0755", info.Mode().Perm())
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatalf("stat type = %T, want *syscall.Stat_t", info.Sys())
	}
	if int(stat.Uid) != os.Getuid() || int(stat.Gid) != os.Getgid() {
		t.Fatalf("uid,gid = %d,%d, want %d,%d", stat.Uid, stat.Gid, os.Getuid(), os.Getgid())
	}
	if _, err := os.Stat(nvidiaPersistencedSocket); !os.IsNotExist(err) {
		t.Fatalf("stale socket stat err = %v, want not exist", err)
	}
	if _, err := os.Stat(nvidiaPersistencedPIDPath); !os.IsNotExist(err) {
		t.Fatalf("stale pid stat err = %v, want not exist", err)
	}
}

func TestEnsureSymlinkCreatesAndReplacesStaleLink(t *testing.T) {
	dir := t.TempDir()
	linkPath := filepath.Join(dir, "run", "shm")

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

func TestRamdiskSizeGBMatchesShellPolicy(t *testing.T) {
	tests := []struct {
		name     string
		memGB    uint64
		wantSize uint64
		wantFB   bool
	}{
		{name: "large", memGB: 128, wantSize: 112},
		{name: "minimum-full", memGB: 32, wantSize: 16},
		{name: "below-minimum", memGB: 31, wantSize: 4, wantFB: true},
		{name: "dev-machine", memGB: 16, wantSize: 4, wantFB: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotSize, gotFB, err := ramdiskSizeGB(tt.memGB * 1024 * 1024)
			if err != nil {
				t.Fatalf("ramdiskSizeGB: %v", err)
			}
			if gotSize != tt.wantSize || gotFB != tt.wantFB {
				t.Fatalf("size,fallback = %d,%t; want %d,%t", gotSize, gotFB, tt.wantSize, tt.wantFB)
			}
		})
	}
}

func TestRamdiskSizeGBFromMeminfo(t *testing.T) {
	path := filepath.Join(t.TempDir(), "meminfo")
	if err := os.WriteFile(path, []byte("MemTotal:       67108864 kB\nMemFree: 1 kB\n"), 0644); err != nil {
		t.Fatal(err)
	}
	sizeGB, fallback, err := ramdiskSizeGBFrom(path)
	if err != nil {
		t.Fatalf("ramdiskSizeGBFrom: %v", err)
	}
	if sizeGB != 48 || fallback {
		t.Fatalf("size,fallback = %d,%t; want 48,false", sizeGB, fallback)
	}

	if err := os.WriteFile(path, []byte("MemFree: 1 kB\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ramdiskSizeGBFrom(path); err == nil {
		t.Fatal("expected missing MemTotal to fail")
	}
}

func TestRuntimeMountLineInterestingIncludesRuntimeMounts(t *testing.T) {
	cases := map[string]bool{
		"25 21 0:21 / /dev/shm rw,nosuid,nodev - tmpfs tmpfs rw,size=524288k":        true,
		"26 21 0:22 / /var/tmp rw,nosuid,nodev - tmpfs tmpfs rw,size=524288k":        true,
		"26 21 0:25 / /mnt/ramdisk rw,nosuid,nodev - tmpfs tmpfs rw,size=117440512k": true,
		"27 21 0:23 / /sys/fs/cgroup rw,nosuid,nodev,noexec - cgroup2 cgroup2 rw":    true,
		"28 21 0:24 / /proc rw,nosuid,nodev,noexec - proc proc rw":                   false,
	}
	for line, want := range cases {
		if got := runtimeMountLineInteresting(line); got != want {
			t.Fatalf("runtimeMountLineInteresting(%q) = %t, want %t", line, got, want)
		}
	}
}

func TestDesiredRaisedRlimitRaisesSoftAndHardFloors(t *testing.T) {
	current := unix.Rlimit{Cur: 1024, Max: 4096}
	got := desiredRaisedRlimit(current, runtimeNOFILELimit, runtimeNOFILELimit)
	if got.Cur != runtimeNOFILELimit || got.Max != runtimeNOFILELimit {
		t.Fatalf("desiredRaisedRlimit = soft=%d hard=%d, want %d/%d", got.Cur, got.Max, runtimeNOFILELimit, runtimeNOFILELimit)
	}
}

func TestDesiredRaisedRlimitPreservesHigherCeilings(t *testing.T) {
	current := unix.Rlimit{Cur: 1048576, Max: unix.RLIM_INFINITY}
	got := desiredRaisedRlimit(current, runtimeNOFILELimit, runtimeNOFILELimit)
	if got != current {
		t.Fatalf("desiredRaisedRlimit lowered %#v to %#v", current, got)
	}
}

func TestDesiredRaisedRlimitKeepsHardAtLeastSoft(t *testing.T) {
	got := desiredRaisedRlimit(unix.Rlimit{Cur: 1, Max: 2}, 8, 4)
	if got.Cur != 8 || got.Max != 8 {
		t.Fatalf("desiredRaisedRlimit soft>hard = soft=%d hard=%d, want 8/8", got.Cur, got.Max)
	}
}

func TestFormatRlimitValue(t *testing.T) {
	if got := formatRlimitValue(unix.RLIM_INFINITY); got != "infinity" {
		t.Fatalf("formatRlimitValue(infinity) = %q", got)
	}
	if got := formatRlimitValue(524288); got != "524288" {
		t.Fatalf("formatRlimitValue(524288) = %q", got)
	}
}

func TestSanitizeSyslogMessage(t *testing.T) {
	got := sanitizeSyslogMessage("\x00notice\nline\r\n")
	if got != `notice\nline` {
		t.Fatalf("sanitizeSyslogMessage = %q", got)
	}
}

func TestNVIDIAPCIDevicesListsOnlyNVIDIADevices(t *testing.T) {
	old := pciDevicesDir
	t.Cleanup(func() { pciDevicesDir = old })

	dir := t.TempDir()
	pciDevicesDir = dir
	nvidia := filepath.Join(dir, "0000:bd:00.0")
	other := filepath.Join(dir, "0000:00:1f.2")
	missingVendor := filepath.Join(dir, "0000:00:1f.3")
	for _, device := range []string{nvidia, other, missingVendor} {
		if err := os.MkdirAll(device, 0755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(nvidia, "vendor"), []byte("0x10de\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(other, "vendor"), []byte("0x8086\n"), 0644); err != nil {
		t.Fatal(err)
	}

	got, err := nvidiaPCIDevices()
	if err != nil {
		t.Fatalf("nvidiaPCIDevices: %v", err)
	}
	if !reflect.DeepEqual(got, []string{"0000:bd:00.0"}) {
		t.Fatalf("nvidiaPCIDevices = %#v, want only NVIDIA device", got)
	}
}

func TestParsePCICapabilitiesDecodesMSIAndMSIX(t *testing.T) {
	config := make([]byte, pciConfigSnapshotLen)
	binary.LittleEndian.PutUint16(config[pciStatusOffset:pciStatusOffset+2], pciStatusCapabilities)
	config[pciHeaderTypeOffset] = 0
	config[pciCapabilityPtrType0] = 0x50

	config[0x50] = pciCapabilityMSI
	config[0x51] = 0x60
	binary.LittleEndian.PutUint16(config[0x52:0x54], 0x0191)

	config[0x60] = pciCapabilityMSIX
	config[0x61] = 0x00
	binary.LittleEndian.PutUint16(config[0x62:0x64], 0x8002)

	got := parsePCICapabilities(config)
	want := []pciCapability{
		{offset: 0x50, id: pciCapabilityMSI, next: 0x60},
		{offset: 0x60, id: pciCapabilityMSIX, next: 0x00},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("capabilities = %#v, want %#v", got, want)
	}

	msi := describePCICapability(config, got[0])
	for _, want := range []string{"id=0x05(MSI)", "msi_enable=true", "address64=true", "per_vector_mask=true"} {
		if !strings.Contains(msi, want) {
			t.Fatalf("MSI summary %q missing %q", msi, want)
		}
	}
	msix := describePCICapability(config, got[1])
	for _, want := range []string{"id=0x11(MSI-X)", "msix_enable=true", "table_size=3"} {
		if !strings.Contains(msix, want) {
			t.Fatalf("MSI-X summary %q missing %q", msix, want)
		}
	}
}

func TestParsePCICapabilitiesRejectsUnsupportedHeadersAndLoops(t *testing.T) {
	config := make([]byte, pciConfigSnapshotLen)
	binary.LittleEndian.PutUint16(config[pciStatusOffset:pciStatusOffset+2], pciStatusCapabilities)
	config[pciHeaderTypeOffset] = 1
	config[pciCapabilityPtrType0] = 0x50
	config[0x50] = pciCapabilityMSI
	if got := parsePCICapabilities(config); len(got) != 0 {
		t.Fatalf("bridge-header capabilities = %#v, want none", got)
	}

	config[pciHeaderTypeOffset] = 0
	config[0x50] = pciCapabilityMSI
	config[0x51] = 0x50
	got := parsePCICapabilities(config)
	if len(got) != 1 || got[0].offset != 0x50 {
		t.Fatalf("looping capabilities = %#v, want one decoded capability", got)
	}
}

func TestHoldNVIDIAPCIEnableReferenceScopesToGPUFunctions(t *testing.T) {
	old := pciDevicesDir
	t.Cleanup(func() { pciDevicesDir = old })

	dir := t.TempDir()
	pciDevicesDir = dir
	fixtures := map[string]struct {
		vendor string
		class  string
		want   string
	}{
		"0000:bd:00.0": {vendor: "0x10de", class: "0x030200", want: "1\n"},
		"0000:bd:00.1": {vendor: "0x10de", class: "0x030000", want: "1\n"},
		"0000:bd:00.2": {vendor: "0x10de", class: "0x068000", want: "0\n"},
		"0000:00:1f.2": {vendor: "0x8086", class: "0x030200", want: "0\n"},
	}
	for device, fixture := range fixtures {
		base := filepath.Join(dir, device)
		if err := os.MkdirAll(base, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(base, "vendor"), []byte(fixture.vendor+"\n"), 0644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(base, "class"), []byte(fixture.class+"\n"), 0644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(base, "enable"), []byte("0\n"), 0644); err != nil {
			t.Fatal(err)
		}
	}

	if err := holdNVIDIAPCIEnableReference(); err != nil {
		t.Fatalf("holdNVIDIAPCIEnableReference: %v", err)
	}
	for device, fixture := range fixtures {
		got, err := os.ReadFile(filepath.Join(dir, device, "enable"))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != fixture.want {
			t.Fatalf("%s enable = %q, want %q", device, got, fixture.want)
		}
	}
}

func TestEnableNVIDIARuntimePowerManagementMatchesStockBindRule(t *testing.T) {
	old := pciDevicesDir
	t.Cleanup(func() { pciDevicesDir = old })

	dir := t.TempDir()
	pciDevicesDir = dir
	fixtures := map[string]struct {
		vendor string
		class  string
		want   string
	}{
		"0000:bd:00.0": {vendor: "0x10de", class: "0x030200", want: "auto\n"},
		"0000:bd:00.1": {vendor: "0x10de", class: "0x030000", want: "auto\n"},
		"0000:bd:00.2": {vendor: "0x10de", class: "0x068000", want: "on\n"},
		"0000:00:1f.2": {vendor: "0x8086", class: "0x030200", want: "on\n"},
	}
	for device, fixture := range fixtures {
		base := filepath.Join(dir, device)
		if err := os.MkdirAll(filepath.Join(base, "power"), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(base, "vendor"), []byte(fixture.vendor+"\n"), 0644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(base, "class"), []byte(fixture.class+"\n"), 0644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(base, "power", "control"), []byte("on\n"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	missingControl := filepath.Join(dir, "0000:bd:00.3")
	if err := os.MkdirAll(missingControl, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(missingControl, "vendor"), []byte("0x10de\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(missingControl, "class"), []byte("0x030200\n"), 0644); err != nil {
		t.Fatal(err)
	}

	if err := enableNVIDIARuntimePowerManagement(); err != nil {
		t.Fatalf("enableNVIDIARuntimePowerManagement: %v", err)
	}
	for device, fixture := range fixtures {
		got, err := os.ReadFile(filepath.Join(dir, device, "power", "control"))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != fixture.want {
			t.Fatalf("%s power/control = %q, want %q", device, got, fixture.want)
		}
	}
}

func TestBootDebugEnabled(t *testing.T) {
	old := procCmdlinePath
	t.Cleanup(func() { procCmdlinePath = old })

	path := filepath.Join(t.TempDir(), "cmdline")
	procCmdlinePath = path
	if err := os.WriteFile(path, []byte("console=hvc0 tinfoil-debug=on root=/dev/mapper/root\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if !bootDebugEnabled() {
		t.Fatal("expected tinfoil-debug=on to enable debug diagnostics")
	}
	if err := os.WriteFile(path, []byte("console=hvc0 tinfoil-debug=off\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if bootDebugEnabled() {
		t.Fatal("expected debug diagnostics to stay disabled")
	}
}

func TestNVIDIAPreRMOpenDebugShellEnabledRequiresDebugAndFlag(t *testing.T) {
	old := procCmdlinePath
	t.Cleanup(func() { procCmdlinePath = old })

	path := filepath.Join(t.TempDir(), "cmdline")
	procCmdlinePath = path

	tests := []struct {
		name    string
		cmdline string
		want    bool
	}{
		{name: "absent", cmdline: "console=hvc0 root=/dev/mapper/root\n"},
		{name: "flag without debug", cmdline: "console=hvc0 tinfoil-nvidia-pre-open-shell=on\n"},
		{name: "debug without flag", cmdline: "console=hvc0 tinfoil-debug=on\n"},
		{name: "substring", cmdline: "console=hvc0 foo=tinfoil-nvidia-pre-open-shell=on tinfoil-debug=on\n"},
		{name: "enabled", cmdline: "console=hvc0 tinfoil-debug=on tinfoil-nvidia-pre-open-shell=on\n", want: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(path, []byte(tc.cmdline), 0644); err != nil {
				t.Fatal(err)
			}
			if got := nvidiaPreRMOpenDebugShellEnabled(); got != tc.want {
				t.Fatalf("nvidiaPreRMOpenDebugShellEnabled() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestNVIDIAPCIEnableHoldDisabledRequiresDebugAndFlag(t *testing.T) {
	old := procCmdlinePath
	t.Cleanup(func() { procCmdlinePath = old })

	path := filepath.Join(t.TempDir(), "cmdline")
	procCmdlinePath = path

	tests := []struct {
		name    string
		cmdline string
		want    bool
	}{
		{name: "absent", cmdline: "console=hvc0 root=/dev/mapper/root\n"},
		{name: "flag without debug", cmdline: "console=hvc0 tinfoil-nvidia-skip-pci-enable-hold=on\n"},
		{name: "debug without flag", cmdline: "console=hvc0 tinfoil-debug=on\n"},
		{name: "substring", cmdline: "console=hvc0 foo=tinfoil-nvidia-skip-pci-enable-hold=on tinfoil-debug=on\n"},
		{name: "enabled", cmdline: "console=hvc0 tinfoil-debug=on tinfoil-nvidia-skip-pci-enable-hold=on\n", want: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(path, []byte(tc.cmdline), 0644); err != nil {
				t.Fatal(err)
			}
			if got := nvidiaPCIEnableHoldDisabled(); got != tc.want {
				t.Fatalf("nvidiaPCIEnableHoldDisabled() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestTinfoilBootTimeoutAllowsDebugShellToOutliveBootTimeout(t *testing.T) {
	old := procCmdlinePath
	t.Cleanup(func() { procCmdlinePath = old })

	path := filepath.Join(t.TempDir(), "cmdline")
	procCmdlinePath = path
	if err := os.WriteFile(path, []byte("console=hvc0 tinfoil-debug=on\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if got := tinfoilBootTimeout(); got != 0 {
		t.Fatalf("tinfoilBootTimeout() = %v, want no child timeout in debug mode", got)
	}

	if err := os.WriteFile(path, []byte("console=hvc0\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if got := tinfoilBootTimeout(); got != bootTimeout {
		t.Fatalf("tinfoilBootTimeout() = %v, want %v", got, bootTimeout)
	}
}

func TestBootContextAllowsDebugShellToOutliveBootTimeout(t *testing.T) {
	old := procCmdlinePath
	t.Cleanup(func() { procCmdlinePath = old })

	path := filepath.Join(t.TempDir(), "cmdline")
	procCmdlinePath = path
	if err := os.WriteFile(path, []byte("console=hvc0 tinfoil-debug=on\n"), 0644); err != nil {
		t.Fatal(err)
	}

	debugCtx, debugCancel := bootContext(context.Background())
	defer debugCancel()
	if _, ok := debugCtx.Deadline(); ok {
		t.Fatal("debug boot context must not have the production boot deadline")
	}

	if err := os.WriteFile(path, []byte("console=hvc0\n"), 0644); err != nil {
		t.Fatal(err)
	}
	prodCtx, prodCancel := bootContext(context.Background())
	defer prodCancel()
	if _, ok := prodCtx.Deadline(); !ok {
		t.Fatal("production boot context must keep the boot deadline")
	}
}

func TestNVIDIARMTraceEnabledRequiresDebugAndLibrary(t *testing.T) {
	oldCmdline := procCmdlinePath
	oldLibrary := nvidiaRMTraceLibrary
	t.Cleanup(func() {
		procCmdlinePath = oldCmdline
		nvidiaRMTraceLibrary = oldLibrary
	})

	dir := t.TempDir()
	procCmdlinePath = filepath.Join(dir, "cmdline")
	nvidiaRMTraceLibrary = filepath.Join(dir, "nvidia-rm-trace.so")

	if err := os.WriteFile(procCmdlinePath, []byte("console=hvc0 tinfoil-debug=on\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if nvidiaRMTraceEnabled() {
		t.Fatal("trace must stay disabled when the preload library is absent")
	}

	if err := os.WriteFile(nvidiaRMTraceLibrary, []byte("trace"), 0644); err != nil {
		t.Fatal(err)
	}
	if !nvidiaRMTraceEnabled() {
		t.Fatal("trace should enable when debug mode and library are present")
	}

	if err := os.WriteFile(procCmdlinePath, []byte("console=hvc0 tinfoil-debug=off\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if nvidiaRMTraceEnabled() {
		t.Fatal("trace must stay disabled without explicit debug mode")
	}
}

func TestWithNVIDIARMTraceEnvReplacesPreloadAndLog(t *testing.T) {
	oldLibrary := nvidiaRMTraceLibrary
	oldLog := nvidiaRMTraceLog
	t.Cleanup(func() {
		nvidiaRMTraceLibrary = oldLibrary
		nvidiaRMTraceLog = oldLog
	})

	nvidiaRMTraceLibrary = "/usr/lib/tinfoil/test-trace.so"
	nvidiaRMTraceLog = "/run/nvidia-persistenced/test-trace.log"

	got := withNVIDIARMTraceEnv([]string{
		"PATH=/usr/bin",
		"LD_PRELOAD=/tmp/old.so",
		nvidiaRMTraceLogEnv + "=/tmp/old.log",
		"FOO=bar",
	})
	want := []string{
		"PATH=/usr/bin",
		"FOO=bar",
		"LD_PRELOAD=/usr/lib/tinfoil/test-trace.so",
		nvidiaRMTraceLogEnv + "=/run/nvidia-persistenced/test-trace.log",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("env = %#v, want %#v", got, want)
	}
}

func TestNVIDIADeviceMinorsFromProcInfo(t *testing.T) {
	old := nvidiaGPUsDir
	t.Cleanup(func() { nvidiaGPUsDir = old })

	dir := t.TempDir()
	nvidiaGPUsDir = dir
	for _, tc := range []struct {
		name string
		info string
	}{
		{"0000:01:00.0", "Model: NVIDIA B300\nDevice Minor: 3\n"},
		{"0000:02:00.0", "Model: NVIDIA B300\nDevice Minor: 1\n"},
		{"0000:03:00.0", "Model: NVIDIA B300\nDevice Minor: 3\n"},
	} {
		gpuDir := filepath.Join(dir, tc.name)
		if err := os.MkdirAll(gpuDir, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(gpuDir, "information"), []byte(tc.info), 0644); err != nil {
			t.Fatal(err)
		}
	}

	got, err := nvidiaDeviceMinors()
	if err != nil {
		t.Fatalf("nvidiaDeviceMinors: %v", err)
	}
	if want := []int{1, 3}; !reflect.DeepEqual(got, want) {
		t.Fatalf("minors = %#v, want %#v", got, want)
	}
}

func TestNVIDIACapabilityFilesSelectDeviceMinorEntries(t *testing.T) {
	old := nvidiaCapabilitiesDir
	t.Cleanup(func() { nvidiaCapabilitiesDir = old })

	dir := t.TempDir()
	nvidiaCapabilitiesDir = dir
	configPath := filepath.Join(dir, "mig", "config")
	monitorPath := filepath.Join(dir, "mig", "monitor")
	fabricPath := filepath.Join(dir, "fabric-imex-mgmt")
	ignoredPath := filepath.Join(dir, "not-a-device")
	for _, path := range []string{configPath, monitorPath, fabricPath, ignoredPath} {
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(configPath, []byte("DeviceFileMinor: 1\nDeviceFileMode: 256\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(monitorPath, []byte("DeviceFileMinor: 2\nDeviceFileMode: 256\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fabricPath, []byte("DeviceFileMinor: 4323\nDeviceFileMode: 256\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ignoredPath, []byte("not a capability device\n"), 0644); err != nil {
		t.Fatal(err)
	}

	got, err := nvidiaCapabilityFiles()
	if err != nil {
		t.Fatalf("nvidiaCapabilityFiles: %v", err)
	}
	want := []string{configPath, monitorPath}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("capability files = %#v, want %#v", got, want)
	}

	nvidiaCapabilitiesDir = filepath.Join(dir, "missing")
	got, err = nvidiaCapabilityFiles()
	if err != nil {
		t.Fatalf("nvidiaCapabilityFiles missing dir: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("missing capability dir returned %#v", got)
	}
}

func TestNVIDIACapabilityDevicesParseMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(path, []byte("DeviceFileMinor: 7\nDeviceFileMode: 256\n"), 0644); err != nil {
		t.Fatal(err)
	}

	got, ok, err := parseNVIDIACapabilityDevice(path)
	if err != nil {
		t.Fatalf("parseNVIDIACapabilityDevice: %v", err)
	}
	if !ok {
		t.Fatal("expected capability device")
	}
	if got.path != path || got.minor != 7 || got.mode != 0400 {
		t.Fatalf("capability = %#v, want path=%s minor=7 mode=0400", got, path)
	}
}

func TestCharDeviceMajors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices")
	data := `
Character devices:
  1 mem
195 nvidia-frontend
236 nvidia-caps
237 nvidia-uvm

Block devices:
  8 sd
`
	if err := os.WriteFile(path, []byte(data), 0644); err != nil {
		t.Fatal(err)
	}

	got, err := charDeviceMajors(path)
	if err != nil {
		t.Fatalf("charDeviceMajors: %v", err)
	}
	for name, want := range map[string]int{
		"nvidia-frontend": 195,
		"nvidia-caps":     236,
		"nvidia-uvm":      237,
	} {
		if got[name] != want {
			t.Fatalf("major[%s] = %d, want %d (all: %#v)", name, got[name], want, got)
		}
	}
	if _, ok := got["sd"]; ok {
		t.Fatalf("block device leaked into char majors: %#v", got)
	}
}

func TestEnsureDevCharSymlinkCreatesRelativeLinksAndRepairsStale(t *testing.T) {
	old := devRootDir
	t.Cleanup(func() { devRootDir = old })

	devRootDir = t.TempDir()
	tests := []struct {
		name   string
		path   string
		major  int
		minor  int
		target string
	}{
		{
			name:   "gpu",
			path:   filepath.Join(devRootDir, "nvidia0"),
			major:  195,
			minor:  0,
			target: "../nvidia0",
		},
		{
			name:   "capability",
			path:   filepath.Join(devRootDir, "nvidia-caps", "nvidia-cap1"),
			major:  236,
			minor:  1,
			target: "../nvidia-caps/nvidia-cap1",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := ensureDevCharSymlink(tc.path, tc.major, tc.minor); err != nil {
				t.Fatalf("ensureDevCharSymlink create: %v", err)
			}
			link := filepath.Join(devRootDir, "char", strconv.Itoa(tc.major)+":"+strconv.Itoa(tc.minor))
			got, err := os.Readlink(link)
			if err != nil {
				t.Fatalf("readlink created link: %v", err)
			}
			if got != tc.target {
				t.Fatalf("link target = %q, want %q", got, tc.target)
			}

			if err := os.Remove(link); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("../stale", link); err != nil {
				t.Fatal(err)
			}
			if err := ensureDevCharSymlink(tc.path, tc.major, tc.minor); err != nil {
				t.Fatalf("ensureDevCharSymlink repair: %v", err)
			}
			got, err = os.Readlink(link)
			if err != nil {
				t.Fatalf("readlink repaired link: %v", err)
			}
			if got != tc.target {
				t.Fatalf("repaired link target = %q, want %q", got, tc.target)
			}
		})
	}
}

func TestEnsureCharNodeAppliesRequestedModeAfterMknod(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nvidia-modeset")
	oldUmask := syscall.Umask(0022)
	t.Cleanup(func() { syscall.Umask(oldUmask) })

	err := ensureCharNode(path, 1, 7, 0666)
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			t.Skipf("mknod not permitted in this test environment: %v", err)
		}
		t.Fatalf("ensureCharNode: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0666 {
		t.Fatalf("mode = %#o, want 0666", info.Mode().Perm())
	}
}
