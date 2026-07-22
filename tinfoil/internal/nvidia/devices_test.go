package nvidia

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func testDevicePaths(t *testing.T) devicePaths {
	t.Helper()
	root := t.TempDir()
	paths := devicePaths{
		pciDevices:   filepath.Join(root, "pci"),
		gpus:         filepath.Join(root, "gpus"),
		capabilities: filepath.Join(root, "capabilities"),
		nvswitches:   filepath.Join(root, "nvswitches"),
		nvswitchMode: filepath.Join(root, "nvswitch-permissions"),
		nvlinkMode:   filepath.Join(root, "nvlink-permissions"),
		procDevices:  filepath.Join(root, "devices"),
		dev:          filepath.Join(root, "dev"),
	}
	for _, path := range []string{paths.pciDevices, paths.gpus, paths.capabilities, paths.nvswitches, paths.dev} {
		if err := os.MkdirAll(path, 0755); err != nil {
			t.Fatal(err)
		}
	}
	return paths
}

func writeTestFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(contents), 0644); err != nil {
		t.Fatal(err)
	}
}

func addPCIFixture(t *testing.T, paths devicePaths, name, vendor, class string, powerControl bool) {
	t.Helper()
	base := filepath.Join(paths.pciDevices, name)
	writeTestFile(t, filepath.Join(base, "vendor"), vendor+"\n")
	writeTestFile(t, filepath.Join(base, "class"), class+"\n")
	writeTestFile(t, filepath.Join(base, "enable"), "0\n")
	if powerControl {
		writeTestFile(t, filepath.Join(base, "power", "control"), "on\n")
	}
}

func TestPCIDiscoveryAndGPUSetupUseExactClasses(t *testing.T) {
	paths := testDevicePaths(t)
	fixtures := map[string]struct {
		vendor string
		class  string
		gpu    bool
		power  bool
	}{
		"0000:01:00.0": {"0x10de", "0x030000", true, true},
		"0000:02:00.0": {"0x10de", "0x030200", true, true},
		"0000:03:00.0": {"0x10de", "0x068000", false, true},
		"0000:04:00.0": {"0x10de", "0x030201", false, true},
		"0000:05:00.0": {"0x1af4", "0x068000", false, true},
	}
	for name, fixture := range fixtures {
		addPCIFixture(t, paths, name, fixture.vendor, fixture.class, fixture.power)
	}
	addPCIFixture(t, paths, "0000:06:00.0", "0x10de", "0x030200", false)

	present, err := hasPCIDevice(paths)
	if err != nil || !present {
		t.Fatalf("hasPCIDevice = %v, %v; want true, nil", present, err)
	}
	nvswitch, err := hasNVSwitch(paths)
	if err != nil || !nvswitch {
		t.Fatalf("hasNVSwitch = %v, %v; want true, nil", nvswitch, err)
	}
	writeTestFile(t, filepath.Join(paths.pciDevices, "0000:03:00.0", "class"), "0x068001\n")
	nvswitch, err = hasNVSwitch(paths)
	if err != nil || nvswitch {
		t.Fatalf("inexact hasNVSwitch = %v, %v; want false, nil", nvswitch, err)
	}
	writeTestFile(t, filepath.Join(paths.pciDevices, "0000:03:00.0", "class"), "0x068000\n")
	if err := holdGPUEnableReferences(paths); err != nil {
		t.Fatalf("holdGPUEnableReferences: %v", err)
	}
	if err := enableGPURuntimePowerManagement(paths); err != nil {
		t.Fatalf("enableGPURuntimePowerManagement: %v", err)
	}

	for name, fixture := range fixtures {
		enable, err := os.ReadFile(filepath.Join(paths.pciDevices, name, "enable"))
		if err != nil {
			t.Fatal(err)
		}
		wantEnable := "0\n"
		if fixture.gpu {
			wantEnable = "1\n"
		}
		if string(enable) != wantEnable {
			t.Errorf("%s enable = %q, want %q", name, enable, wantEnable)
		}
		control, err := os.ReadFile(filepath.Join(paths.pciDevices, name, "power", "control"))
		if err != nil {
			t.Fatal(err)
		}
		wantControl := "on\n"
		if fixture.gpu {
			wantControl = "auto\n"
		}
		if string(control) != wantControl {
			t.Errorf("%s power/control = %q, want %q", name, control, wantControl)
		}
	}
}

func TestHasPCIDeviceUsesSupportedGPUAndNVSwitchClasses(t *testing.T) {
	tests := []struct {
		name  string
		class string
		want  bool
	}{
		{name: "VGA controller", class: "0x030000", want: true},
		{name: "3D controller", class: "0x030200", want: true},
		{name: "NVSwitch", class: "0x068000", want: true},
		{name: "HDA controller", class: "0x040300", want: false},
		{name: "inexact 3D controller", class: "0x030201", want: false},
		{name: "inexact NVSwitch", class: "0x068001", want: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			paths := testDevicePaths(t)
			addPCIFixture(t, paths, "0000:01:00.0", "0x10de", test.class, false)

			present, err := hasPCIDevice(paths)
			if err != nil || present != test.want {
				t.Fatalf("hasPCIDevice = %v, %v; want %v, nil", present, err, test.want)
			}
		})
	}
}

func TestNVIDIAPresenceAndNVSwitchErrorsAreReported(t *testing.T) {
	paths := testDevicePaths(t)
	present, err := hasPCIDevice(paths)
	if err != nil || present {
		t.Fatalf("empty hasPCIDevice = %v, %v; want false, nil", present, err)
	}
	writeTestFile(t, filepath.Join(paths.pciDevices, "0000:01:00.0", "vendor"), "invalid\n")
	if _, err := hasPCIDevice(paths); err == nil {
		t.Fatal("hasPCIDevice accepted an invalid vendor")
	}
	if _, err := hasNVSwitch(paths); err == nil {
		t.Fatal("hasNVSwitch accepted an invalid vendor")
	}
}

func TestGPUDeviceMinorsUseOnlyProcInformation(t *testing.T) {
	paths := testDevicePaths(t)
	fixtures := map[string]string{
		"0000:01:00.0": "Model: B300\nDevice Minor: 7\n",
		"0000:02:00.0": "Device Minor: 2\n",
		"0000:03:00.0": "Device Minor: 7\n",
	}
	for name, contents := range fixtures {
		writeTestFile(t, filepath.Join(paths.gpus, name, "information"), contents)
	}
	writeTestFile(t, filepath.Join(paths.gpus, "not-a-directory"), "Device Minor: 9\n")

	got, err := nvidiaDeviceMinors(paths.gpus)
	if err != nil {
		t.Fatalf("nvidiaDeviceMinors: %v", err)
	}
	if want := []int{2, 7}; !reflect.DeepEqual(got, want) {
		t.Fatalf("nvidiaDeviceMinors = %v, want %v", got, want)
	}

	writeTestFile(t, filepath.Join(paths.gpus, "0000:04:00.0", "information"), "Model: B300\n")
	if _, err := nvidiaDeviceMinors(paths.gpus); err == nil {
		t.Fatal("nvidiaDeviceMinors accepted missing Device Minor")
	}
}

func TestCapabilityDiscoveryIsBoundedAndPreservesModes(t *testing.T) {
	paths := testDevicePaths(t)
	config := filepath.Join(paths.capabilities, "mig", "config")
	monitor := filepath.Join(paths.capabilities, "mig", "monitor")
	writeTestFile(t, config, "DeviceFileMinor: 1\nDeviceFileMode: 256\n")
	writeTestFile(t, monitor, "DeviceFileMinor: 2\nDeviceFileMode: 288\n")
	writeTestFile(t, filepath.Join(paths.capabilities, "fabric-imex-mgmt"),
		"DeviceFileMinor: 3\nDeviceFileMode: 511\n")
	writeTestFile(t, filepath.Join(paths.capabilities, "mig", "unexpected"),
		"DeviceFileMinor: 4\nDeviceFileMode: 511\n")

	got, err := nvidiaCapabilityDevices(paths.capabilities)
	if err != nil {
		t.Fatalf("nvidiaCapabilityDevices: %v", err)
	}
	want := []capabilityDevice{
		{path: config, minor: 1, mode: 0400},
		{path: monitor, minor: 2, mode: 0440},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("capabilities = %#v, want %#v", got, want)
	}

	if err := os.Remove(config); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(monitor, config); err != nil {
		t.Fatal(err)
	}
	if _, err := nvidiaCapabilityDevices(paths.capabilities); err == nil {
		t.Fatal("capability discovery followed a descriptor symlink")
	}
}

func TestCapabilityParserFailsClosed(t *testing.T) {
	tests := []string{
		"DeviceFileMode: 256\n",
		"DeviceFileMinor: -1\n",
		"DeviceFileMinor: 1\nDeviceFileMode: 512\n",
		"DeviceFileMinor: 1\nDeviceFileMinor: 2\n",
	}
	for index, contents := range tests {
		t.Run(strconv.Itoa(index), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config")
			writeTestFile(t, path, contents)
			if _, err := parseCapabilityDevice(path); err == nil {
				t.Fatalf("parseCapabilityDevice accepted %q", contents)
			}
		})
	}
}

func TestCharacterDeviceMajorsUseOnlyCharacterSection(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices")
	writeTestFile(t, path, `Character devices:
  1 mem
195 nvidia-frontend
236 nvidia-caps
237 nvidia-uvm
238 nvidia-nvlink
239 nvidia-nvswitch

Block devices:
  8 nvidia
`)
	got, err := charDeviceMajors(path)
	if err != nil {
		t.Fatalf("charDeviceMajors: %v", err)
	}
	want := map[string]int{"nvidia-frontend": 195, "nvidia-caps": 236, "nvidia-uvm": 237,
		"nvidia-nvlink": 238, "nvidia-nvswitch": 239}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("majors = %v, want %v", got, want)
	}
}

func TestInterconnectDevicesCoverMultipleSwitchesAndNVLink(t *testing.T) {
	paths := testDevicePaths(t)
	addPCIFixture(t, paths, "0000:01:00.0", "0x10de", "0x068000", false)
	if _, err := nvidiaInterconnectDevices(paths, nil); err == nil {
		t.Fatal("NVSwitch hardware without driver majors was accepted")
	}
	for _, name := range []string{"0000:01:00.0", "0000:02:00.0"} {
		if err := os.Mkdir(filepath.Join(paths.nvswitches, name), 0755); err != nil {
			t.Fatal(err)
		}
	}
	writeTestFile(t, paths.nvswitchMode, "DeviceFileMode: 438\n")
	writeTestFile(t, paths.nvlinkMode, "DeviceFileMode: 432\n")
	majors := map[string]int{"nvidia-nvswitch": 239, "nvidia-nvlink": 238}
	got, err := nvidiaInterconnectDevices(paths, majors)
	if err != nil {
		t.Fatalf("nvidiaInterconnectDevices: %v", err)
	}
	want := []charDevice{
		{path: filepath.Join(paths.dev, "nvidia-nvswitchctl"), major: 239, minor: 255, mode: 0666},
		{path: filepath.Join(paths.dev, "nvidia-nvswitch0"), major: 239, minor: 0, mode: 0666},
		{path: filepath.Join(paths.dev, "nvidia-nvswitch1"), major: 239, minor: 1, mode: 0666},
		{path: filepath.Join(paths.dev, "nvidia-nvlink"), major: 238, minor: 0, mode: 0660},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("interconnect devices = %#v, want %#v", got, want)
	}
	writeTestFile(t, paths.nvswitchMode, "DeviceFileMode: malformed\n")
	if _, err := nvidiaInterconnectDevices(paths, majors); err == nil {
		t.Fatal("malformed NVSwitch permissions were accepted")
	}
}

func TestDevCharSymlinkIsBoundedAndRepairsStaleLinks(t *testing.T) {
	paths := testDevicePaths(t)
	device := charDevice{
		path:  filepath.Join(paths.dev, "nvidia-caps", "nvidia-cap1"),
		major: 236,
		minor: 1,
		mode:  0400,
	}
	if err := ensureDevCharSymlink(paths.dev, device); err != nil {
		t.Fatalf("create symlink: %v", err)
	}
	link := filepath.Join(paths.dev, "char", "236:1")
	if got, err := os.Readlink(link); err != nil || got != "../nvidia-caps/nvidia-cap1" {
		t.Fatalf("link = %q, %v", got, err)
	}

	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../stale", link); err != nil {
		t.Fatal(err)
	}
	if err := ensureDevCharSymlink(paths.dev, device); err != nil {
		t.Fatalf("repair symlink: %v", err)
	}
	if got, err := os.Readlink(link); err != nil || got != "../nvidia-caps/nvidia-cap1" {
		t.Fatalf("repaired link = %q, %v", got, err)
	}

	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, link, "do not replace\n")
	if err := ensureDevCharSymlink(paths.dev, device); err == nil {
		t.Fatal("ensureDevCharSymlink replaced a non-symlink")
	}
	device.path = filepath.Join(paths.dev, "..", "outside")
	if err := ensureDevCharSymlink(paths.dev, device); err == nil {
		t.Fatal("ensureDevCharSymlink accepted an escaping device path")
	}
}

func TestEnsureCharNodeRecreatesOnlyStaleCharacterDevices(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nvidia-nvswitch0")
	oldUmask := syscall.Umask(0022)
	t.Cleanup(func() { syscall.Umask(oldUmask) })

	oldDev := int(unix.Mkdev(1, 3))
	if err := unix.Mknod(path, unix.S_IFCHR|0600, oldDev); err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			t.Skipf("mknod not permitted: %v", err)
		}
		t.Fatal(err)
	}
	device := charDevice{path: path, major: 1, minor: 7, mode: 0660}
	if err := ensureCharNode(device); err != nil {
		t.Fatalf("ensureCharNode: %v", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	major, minor, err := charDeviceNumber(info)
	if err != nil {
		t.Fatal(err)
	}
	if major != 1 || minor != 7 || info.Mode().Perm() != 0660 {
		t.Fatalf("node = %d:%d mode %#o, want 1:7 mode 0660", major, minor, info.Mode().Perm())
	}

	regular := filepath.Join(t.TempDir(), "nvidiactl")
	writeTestFile(t, regular, "keep\n")
	device = charDevice{path: regular, major: 1, minor: 3, mode: 0666}
	if err := ensureCharNode(device); err == nil {
		t.Fatal("ensureCharNode replaced a regular file")
	}
	if contents, err := os.ReadFile(regular); err != nil || string(contents) != "keep\n" {
		t.Fatalf("regular file changed: %q, %v", contents, err)
	}
}

func TestSetupDeviceNodesFailsBeforeReplacingRequiredPaths(t *testing.T) {
	paths := testDevicePaths(t)
	writeTestFile(t, paths.procDevices, "Character devices:\n195 nvidia-frontend\n")
	writeTestFile(t, filepath.Join(paths.dev, "nvidiactl"), "keep\n")

	err := setupDeviceNodes(paths)
	if err == nil || !strings.Contains(err.Error(), "not a character device") {
		t.Fatalf("setupDeviceNodes error = %v, want required node error", err)
	}
	if contents, err := os.ReadFile(filepath.Join(paths.dev, "nvidiactl")); err != nil || string(contents) != "keep\n" {
		t.Fatalf("required path changed: %q, %v", contents, err)
	}

	writeTestFile(t, filepath.Join(paths.capabilities, "mig", "config"),
		"DeviceFileMinor: 1\nDeviceFileMode: 256\n")
	err = setupDeviceNodes(paths)
	if err == nil || !strings.Contains(err.Error(), "without nvidia-caps") {
		t.Fatalf("setupDeviceNodes capability error = %v", err)
	}
}
