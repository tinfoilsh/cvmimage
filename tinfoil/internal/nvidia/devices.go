package nvidia

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

const (
	nvidiaPCIVendor = 0x10de

	pciClassVGAController = 0x030000
	pciClass3DController  = 0x030200
	pciClassNVSwitch      = 0x068000

	nvidiaCtlMinor         = 255
	nvidiaModesetMinor     = 254
	nvidiaUVMMinor         = 0
	nvidiaUVMToolsMinor    = 1
	nvidiaNVLinkMinor      = 0
	nvidiaNVSwitchCtlMinor = 255
	maxNVSwitches          = 64

	maxDeviceMajor = (1 << 12) - 1
	maxDeviceMinor = (1 << 20) - 1
)

var allowedCapabilityFiles = [...]string{
	"mig/config",
	"mig/monitor",
}

type devicePaths struct {
	pciDevices   string
	gpus         string
	capabilities string
	nvswitches   string
	nvswitchMode string
	nvlinkMode   string
	procDevices  string
	dev          string
}

var systemDevicePaths = devicePaths{
	pciDevices:   "/sys/bus/pci/devices",
	gpus:         "/proc/driver/nvidia/gpus",
	capabilities: "/proc/driver/nvidia/capabilities",
	nvswitches:   "/proc/driver/nvidia-nvswitch/devices",
	nvswitchMode: "/proc/driver/nvidia-nvswitch/permissions",
	nvlinkMode:   "/proc/driver/nvidia-nvlink/permissions",
	procDevices:  "/proc/devices",
	dev:          "/dev",
}

type pciDevice struct {
	name  string
	class uint64
}

type capabilityDevice struct {
	path  string
	minor int
	mode  os.FileMode
}

type charDevice struct {
	path  string
	major int
	minor int
	mode  os.FileMode
}

// HasPCIDevice reports whether sysfs contains a supported NVIDIA GPU or
// NVSwitch PCI function.
func HasPCIDevice() (bool, error) {
	return hasPCIDevice(systemDevicePaths)
}

// HasNVSwitch reports whether sysfs contains an NVIDIA NVSwitch function.
func HasNVSwitch() (bool, error) {
	return hasNVSwitch(systemDevicePaths)
}

func hasNVSwitch(paths devicePaths) (bool, error) {
	devices, err := nvidiaPCIDevices(paths)
	if err != nil {
		return false, err
	}
	for _, device := range devices {
		if device.class == pciClassNVSwitch {
			return true, nil
		}
	}
	return false, nil
}

// HoldGPUEnableReferences increments the PCI enable reference for each NVIDIA
// VGA or 3D controller. It must run before the NVIDIA driver probes the GPUs.
func HoldGPUEnableReferences() error {
	return holdGPUEnableReferences(systemDevicePaths)
}

// EnableGPURuntimePowerManagement switches NVIDIA VGA and 3D controllers to
// automatic runtime power management when the kernel exposes that control.
func EnableGPURuntimePowerManagement() error {
	return enableGPURuntimePowerManagement(systemDevicePaths)
}

// SetupDeviceNodes creates and verifies the NVIDIA character devices and their
// /dev/char links using kernel-assigned majors and NVIDIA-assigned minors.
func SetupDeviceNodes() error {
	return setupDeviceNodes(systemDevicePaths)
}

func hasPCIDevice(paths devicePaths) (bool, error) {
	devices, err := nvidiaPCIDevices(paths)
	if err != nil {
		return false, err
	}
	for _, device := range devices {
		if isSupportedPCIClass(device.class) {
			return true, nil
		}
	}
	return false, nil
}

func nvidiaPCIDevices(paths devicePaths) ([]pciDevice, error) {
	entries, err := os.ReadDir(paths.pciDevices)
	if err != nil {
		return nil, fmt.Errorf("read PCI devices: %w", err)
	}

	var devices []pciDevice
	for _, entry := range entries {
		base := filepath.Join(paths.pciDevices, entry.Name())
		vendor, err := readHexAttribute(filepath.Join(base, "vendor"))
		if err != nil {
			return nil, fmt.Errorf("read PCI vendor for %s: %w", entry.Name(), err)
		}
		if vendor != nvidiaPCIVendor {
			continue
		}
		class, err := readHexAttribute(filepath.Join(base, "class"))
		if err != nil {
			return nil, fmt.Errorf("read NVIDIA PCI class for %s: %w", entry.Name(), err)
		}
		devices = append(devices, pciDevice{name: entry.Name(), class: class})
	}
	sort.Slice(devices, func(i, j int) bool {
		return devices[i].name < devices[j].name
	})
	return devices, nil
}

func readHexAttribute(path string) (uint64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	value := strings.TrimSpace(string(data))
	parsed, err := strconv.ParseUint(value, 0, 32)
	if err != nil {
		return 0, fmt.Errorf("parse %s value %q: %w", path, value, err)
	}
	return parsed, nil
}

func isGPUClass(class uint64) bool {
	return class == pciClassVGAController || class == pciClass3DController
}

func isSupportedPCIClass(class uint64) bool {
	return isGPUClass(class) || class == pciClassNVSwitch
}

func holdGPUEnableReferences(paths devicePaths) error {
	devices, err := nvidiaPCIDevices(paths)
	if err != nil {
		return err
	}
	for _, device := range devices {
		if !isGPUClass(device.class) {
			continue
		}
		path := filepath.Join(paths.pciDevices, device.name, "enable")
		if err := os.WriteFile(path, []byte("1\n"), 0644); err != nil {
			return fmt.Errorf("hold PCI enable reference for %s: %w", device.name, err)
		}
	}
	return nil
}

func enableGPURuntimePowerManagement(paths devicePaths) error {
	devices, err := nvidiaPCIDevices(paths)
	if err != nil {
		return err
	}
	for _, device := range devices {
		if !isGPUClass(device.class) {
			continue
		}
		path := filepath.Join(paths.pciDevices, device.name, "power", "control")
		if err := os.WriteFile(path, []byte("auto\n"), 0644); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return fmt.Errorf("enable runtime power management for %s: %w", device.name, err)
		}
	}
	return nil
}

func setupDeviceNodes(paths devicePaths) error {
	majors, err := charDeviceMajors(paths.procDevices)
	if err != nil {
		return fmt.Errorf("read character device majors: %w", err)
	}
	frontend, ok := firstMajor(majors, "nvidia-frontend", "nvidia")
	if !ok {
		return errors.New("missing nvidia-frontend character device major")
	}

	gpuMinors, err := nvidiaDeviceMinors(paths.gpus)
	if err != nil {
		return fmt.Errorf("discover NVIDIA GPU minors: %w", err)
	}
	capabilities, err := nvidiaCapabilityDevices(paths.capabilities)
	if err != nil {
		return fmt.Errorf("discover NVIDIA capability devices: %w", err)
	}

	devices := []charDevice{
		{
			path:  filepath.Join(paths.dev, "nvidiactl"),
			major: frontend,
			minor: nvidiaCtlMinor,
			mode:  0666,
		},
		{
			path:  filepath.Join(paths.dev, "nvidia-modeset"),
			major: frontend,
			minor: nvidiaModesetMinor,
			mode:  0666,
		},
	}
	for _, minor := range gpuMinors {
		devices = append(devices, charDevice{
			path:  filepath.Join(paths.dev, "nvidia"+strconv.Itoa(minor)),
			major: frontend,
			minor: minor,
			mode:  0666,
		})
	}

	if uvm, ok := majors["nvidia-uvm"]; ok {
		devices = append(devices,
			charDevice{
				path:  filepath.Join(paths.dev, "nvidia-uvm"),
				major: uvm,
				minor: nvidiaUVMMinor,
				mode:  0666,
			},
			charDevice{
				path:  filepath.Join(paths.dev, "nvidia-uvm-tools"),
				major: uvm,
				minor: nvidiaUVMToolsMinor,
				mode:  0666,
			},
		)
	}

	if len(capabilities) > 0 {
		caps, ok := majors["nvidia-caps"]
		if !ok {
			return errors.New("NVIDIA capability descriptors exist without nvidia-caps character device major")
		}
		for _, capability := range capabilities {
			devices = append(devices, charDevice{
				path:  filepath.Join(paths.dev, "nvidia-caps", "nvidia-cap"+strconv.Itoa(capability.minor)),
				major: caps,
				minor: capability.minor,
				mode:  capability.mode,
			})
		}
	}
	interconnects, err := nvidiaInterconnectDevices(paths, majors)
	if err != nil {
		return fmt.Errorf("discover NVIDIA interconnect devices: %w", err)
	}
	devices = append(devices, interconnects...)

	if err := validateCharDevices(devices); err != nil {
		return err
	}
	for _, device := range devices {
		if err := ensureCharDevice(paths.dev, device); err != nil {
			return err
		}
	}
	return nil
}

func nvidiaInterconnectDevices(paths devicePaths, majors map[string]int) ([]charDevice, error) {
	hasSwitch, err := hasNVSwitch(paths)
	if err != nil {
		return nil, err
	}
	switchMajor, switchLoaded := majors["nvidia-nvswitch"]
	nvlinkMajor, nvlinkLoaded := majors["nvidia-nvlink"]
	if hasSwitch && (!switchLoaded || !nvlinkLoaded) {
		return nil, errors.New("NVSwitch PCI device requires nvidia-nvswitch and nvidia-nvlink character majors")
	}

	var devices []charDevice
	if switchLoaded {
		mode, err := deviceFileMode(paths.nvswitchMode)
		if err != nil {
			return nil, err
		}
		minors, err := nvidiaNVSwitchMinors(paths.nvswitches)
		if err != nil {
			return nil, err
		}
		devices = append(devices, charDevice{
			path: filepath.Join(paths.dev, "nvidia-nvswitchctl"), major: switchMajor,
			minor: nvidiaNVSwitchCtlMinor, mode: mode,
		})
		for _, minor := range minors {
			devices = append(devices, charDevice{
				path:  filepath.Join(paths.dev, "nvidia-nvswitch"+strconv.Itoa(minor)),
				major: switchMajor, minor: minor, mode: mode,
			})
		}
	}
	if nvlinkLoaded {
		mode, err := deviceFileMode(paths.nvlinkMode)
		if err != nil {
			return nil, err
		}
		devices = append(devices, charDevice{
			path: filepath.Join(paths.dev, "nvidia-nvlink"), major: nvlinkMajor,
			minor: nvidiaNVLinkMinor, mode: mode,
		})
	}
	return devices, nil
}

func nvidiaNVSwitchMinors(root string) ([]int, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	// The driver exposes one directory per bound switch but no minor field.
	// During static boot probing it allocates the lowest free minors from zero.
	if len(entries) > maxNVSwitches {
		return nil, fmt.Errorf("NVSwitch count %d exceeds driver maximum %d", len(entries), maxNVSwitches)
	}
	minors := make([]int, len(entries))
	for index, entry := range entries {
		if !entry.IsDir() {
			return nil, fmt.Errorf("unexpected non-directory NVSwitch entry %s", entry.Name())
		}
		minors[index] = index
	}
	return minors, nil
}

func deviceFileMode(path string) (os.FileMode, error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	var (
		value string
		found bool
	)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		key, candidate, ok := strings.Cut(scanner.Text(), ":")
		if !ok || strings.TrimSpace(key) != "DeviceFileMode" {
			continue
		}
		if found {
			return 0, fmt.Errorf("%s contains duplicate DeviceFileMode fields", path)
		}
		value = strings.TrimSpace(candidate)
		found = true
	}
	if err := scanner.Err(); err != nil {
		return 0, err
	}
	mode, err := strconv.ParseUint(value, 0, 32)
	if err != nil || mode > 0777 {
		return 0, fmt.Errorf("invalid DeviceFileMode in %s: %q", path, value)
	}
	return os.FileMode(mode), nil
}

func nvidiaDeviceMinors(root string) ([]int, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	minors := make(map[int]struct{})
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		path := filepath.Join(root, entry.Name(), "information")
		minor, err := parseGPUDeviceMinor(path)
		if err != nil {
			return nil, err
		}
		minors[minor] = struct{}{}
	}

	result := make([]int, 0, len(minors))
	for minor := range minors {
		result = append(result, minor)
	}
	sort.Ints(result)
	return result, nil
}

func parseGPUDeviceMinor(path string) (int, error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	var (
		value string
		found bool
	)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		key, candidate, ok := strings.Cut(scanner.Text(), ":")
		if !ok || strings.TrimSpace(key) != "Device Minor" {
			continue
		}
		if found {
			return 0, fmt.Errorf("%s contains duplicate Device Minor fields", path)
		}
		value = strings.TrimSpace(candidate)
		found = true
	}
	if err := scanner.Err(); err != nil {
		return 0, err
	}
	if !found {
		return 0, fmt.Errorf("%s has no Device Minor field", path)
	}
	minor, err := parseDeviceNumber(value, maxDeviceMinor)
	if err != nil {
		return 0, fmt.Errorf("invalid Device Minor in %s: %w", path, err)
	}
	return minor, nil
}

func nvidiaCapabilityDevices(root string) ([]capabilityDevice, error) {
	devices := make([]capabilityDevice, 0, len(allowedCapabilityFiles))
	minors := make(map[int]string)
	for _, relative := range allowedCapabilityFiles {
		path := filepath.Join(root, filepath.FromSlash(relative))
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("capability descriptor %s is not a regular file", path)
		}
		device, err := parseCapabilityDevice(path)
		if err != nil {
			return nil, err
		}
		if previous, ok := minors[device.minor]; ok {
			return nil, fmt.Errorf("capability descriptors %s and %s use minor %d", previous, path, device.minor)
		}
		minors[device.minor] = path
		devices = append(devices, device)
	}
	return devices, nil
}

func parseCapabilityDevice(path string) (capabilityDevice, error) {
	file, err := os.Open(path)
	if err != nil {
		return capabilityDevice{}, err
	}
	defer file.Close()

	var (
		minorValue string
		modeValue  string
		minorFound bool
		modeFound  bool
	)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		key, value, ok := strings.Cut(scanner.Text(), ":")
		if !ok {
			continue
		}
		switch strings.TrimSpace(key) {
		case "DeviceFileMinor":
			if minorFound {
				return capabilityDevice{}, fmt.Errorf("%s contains duplicate DeviceFileMinor fields", path)
			}
			minorValue = strings.TrimSpace(value)
			minorFound = true
		case "DeviceFileMode":
			if modeFound {
				return capabilityDevice{}, fmt.Errorf("%s contains duplicate DeviceFileMode fields", path)
			}
			modeValue = strings.TrimSpace(value)
			modeFound = true
		}
	}
	if err := scanner.Err(); err != nil {
		return capabilityDevice{}, err
	}
	if !minorFound {
		return capabilityDevice{}, fmt.Errorf("%s has no DeviceFileMinor field", path)
	}
	minor, err := parseDeviceNumber(minorValue, maxDeviceMinor)
	if err != nil {
		return capabilityDevice{}, fmt.Errorf("invalid DeviceFileMinor in %s: %w", path, err)
	}

	mode := os.FileMode(0600)
	if modeFound {
		value, err := strconv.ParseUint(modeValue, 0, 32)
		if err != nil || value > 0777 {
			return capabilityDevice{}, fmt.Errorf("invalid DeviceFileMode in %s: %q", path, modeValue)
		}
		mode = os.FileMode(value)
	}
	return capabilityDevice{path: path, minor: minor, mode: mode}, nil
}

func parseDeviceNumber(value string, maximum int) (int, error) {
	parsed, err := strconv.ParseUint(value, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("parse %q: %w", value, err)
	}
	if parsed > uint64(maximum) {
		return 0, fmt.Errorf("%d exceeds maximum %d", parsed, maximum)
	}
	return int(parsed), nil
}

func charDeviceMajors(path string) (map[string]int, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	majors := make(map[string]int)
	inCharacterDevices := false
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		switch line {
		case "Character devices:":
			inCharacterDevices = true
			continue
		case "Block devices:":
			inCharacterDevices = false
			continue
		}
		if !inCharacterDevices {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 || !wantedDeviceMajor(fields[1]) {
			continue
		}
		major, err := parseDeviceNumber(fields[0], maxDeviceMajor)
		if err != nil {
			return nil, fmt.Errorf("invalid major for %s: %w", fields[1], err)
		}
		if previous, ok := majors[fields[1]]; ok && previous != major {
			return nil, fmt.Errorf("conflicting majors for %s: %d and %d", fields[1], previous, major)
		}
		majors[fields[1]] = major
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return majors, nil
}

func wantedDeviceMajor(name string) bool {
	switch name {
	case "nvidia-frontend", "nvidia", "nvidia-uvm", "nvidia-caps",
		"nvidia-nvswitch", "nvidia-nvlink":
		return true
	default:
		return false
	}
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

func validateCharDevices(devices []charDevice) error {
	numbers := make(map[string]string)
	for _, device := range devices {
		if err := validateDeviceNumber(device.major, device.minor); err != nil {
			return fmt.Errorf("invalid character device %s: %w", device.path, err)
		}
		if device.mode != device.mode.Perm() {
			return fmt.Errorf("invalid character device mode for %s: %#o", device.path, device.mode)
		}
		key := fmt.Sprintf("%d:%d", device.major, device.minor)
		if previous, ok := numbers[key]; ok && previous != device.path {
			return fmt.Errorf("character device number %s is assigned to both %s and %s", key, previous, device.path)
		}
		numbers[key] = device.path
	}
	return nil
}

func validateDeviceNumber(major, minor int) error {
	if major < 0 || major > maxDeviceMajor {
		return fmt.Errorf("major %d is outside 0..%d", major, maxDeviceMajor)
	}
	if minor < 0 || minor > maxDeviceMinor {
		return fmt.Errorf("minor %d is outside 0..%d", minor, maxDeviceMinor)
	}
	return nil
}

func ensureCharDevice(devRoot string, device charDevice) error {
	if err := ensureCharNode(device); err != nil {
		return fmt.Errorf("ensure NVIDIA character device %s: %w", device.path, err)
	}
	if err := ensureDevCharSymlink(devRoot, device); err != nil {
		return fmt.Errorf("ensure /dev/char link for %s: %w", device.path, err)
	}
	return nil
}

func ensureCharNode(device charDevice) error {
	if err := validateDeviceNumber(device.major, device.minor); err != nil {
		return err
	}
	if device.mode != device.mode.Perm() {
		return fmt.Errorf("invalid mode %#o", device.mode)
	}

	info, err := os.Lstat(device.path)
	if err == nil {
		actualMajor, actualMinor, err := charDeviceNumber(info)
		if err != nil {
			return err
		}
		if actualMajor == device.major && actualMinor == device.minor {
			if err := os.Chmod(device.path, device.mode); err != nil {
				return fmt.Errorf("chmod: %w", err)
			}
			return nil
		}
		if err := os.Remove(device.path); err != nil {
			return fmt.Errorf("remove stale character device: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	if err := ensureDirectory(filepath.Dir(device.path)); err != nil {
		return err
	}
	dev := int(unix.Mkdev(uint32(device.major), uint32(device.minor)))
	if err := unix.Mknod(device.path, uint32(unix.S_IFCHR|device.mode.Perm()), dev); err != nil {
		return fmt.Errorf("mknod %d:%d: %w", device.major, device.minor, err)
	}
	if err := os.Chmod(device.path, device.mode); err != nil {
		return fmt.Errorf("chmod: %w", err)
	}
	info, err = os.Lstat(device.path)
	if err != nil {
		return fmt.Errorf("verify created character device: %w", err)
	}
	actualMajor, actualMinor, err := charDeviceNumber(info)
	if err != nil {
		return fmt.Errorf("verify created character device: %w", err)
	}
	if actualMajor != device.major || actualMinor != device.minor {
		return fmt.Errorf("created character device is %d:%d, want %d:%d", actualMajor, actualMinor, device.major, device.minor)
	}
	return nil
}

func charDeviceNumber(info os.FileInfo) (int, int, error) {
	if info.Mode()&os.ModeCharDevice == 0 {
		return 0, 0, errors.New("existing path is not a character device")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, errors.New("character device has no Linux stat data")
	}
	return int(unix.Major(uint64(stat.Rdev))), int(unix.Minor(uint64(stat.Rdev))), nil
}

func ensureDevCharSymlink(devRoot string, device charDevice) error {
	relativeDevice, err := filepath.Rel(devRoot, device.path)
	if err != nil {
		return err
	}
	if relativeDevice == "." || relativeDevice == ".." ||
		strings.HasPrefix(relativeDevice, ".."+string(filepath.Separator)) ||
		filepath.IsAbs(relativeDevice) {
		return fmt.Errorf("device path %s escapes %s", device.path, devRoot)
	}

	charDir := filepath.Join(devRoot, "char")
	if err := ensureDirectory(charDir); err != nil {
		return err
	}
	link := filepath.Join(charDir, fmt.Sprintf("%d:%d", device.major, device.minor))
	target, err := filepath.Rel(charDir, device.path)
	if err != nil {
		return err
	}

	info, err := os.Lstat(link)
	if err == nil {
		if info.Mode()&os.ModeSymlink == 0 {
			return errors.New("existing /dev/char path is not a symlink")
		}
		current, err := os.Readlink(link)
		if err != nil {
			return err
		}
		if current == target {
			return nil
		}
		if err := os.Remove(link); err != nil {
			return fmt.Errorf("remove stale symlink: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	if err := os.Symlink(target, link); err != nil {
		return fmt.Errorf("create symlink to %s: %w", target, err)
	}
	current, err := os.Readlink(link)
	if err != nil {
		return fmt.Errorf("verify symlink: %w", err)
	}
	if current != target {
		return fmt.Errorf("symlink target is %s, want %s", current, target)
	}
	return nil
}

func ensureDirectory(path string) error {
	if err := os.MkdirAll(path, 0755); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", path)
	}
	return nil
}
