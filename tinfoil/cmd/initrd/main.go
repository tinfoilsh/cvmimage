package main

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"tinfoil/internal/boot"
)

const (
	programMarker            = "tinfoil-initrd-go-v6"
	initrdModuleManifest     = "/usr/lib/tinfoil/initrd-modules"
	initrdModuleModeKey      = "tinfoil-initrd-modules"
	initrdModuleManifestMode = "manifest"
	initrdModuleBuiltinMode  = "builtin"
	maxInitrdModules         = 2
	veritySuperblockLen      = 512
)

const (
	dmName            = "root"
	dmControlNode     = "/dev/mapper/control"
	dmRootNode        = "/dev/mapper/root"
	dmIoctlSize       = 312
	dmIoctlDataStart  = dmIoctlSize
	dmTargetSpecSize  = 40
	dmNameOffset      = 48
	dmDevOffset       = 40
	dmTargetSpecAlign = 8

	dmVersionMajor = 4
	dmVersionMinor = 0
	dmVersionPatch = 0

	dmVersionCmd    = 0
	dmDevCreateCmd  = 3
	dmDevSuspendCmd = 6
	dmDevStatusCmd  = 7
	dmTableLoadCmd  = 9

	dmReadOnlyFlag      = 1 << 0
	dmExistsFlag        = 0x00000004
	dmActivePresentFlag = 1 << 5
	dmIoctlMagic        = 0xfd
	dmIoctlReadWrite    = 3
)

const (
	dmVersionIOCTL    = uintptr((dmIoctlReadWrite << 30) | (dmIoctlSize << 16) | (dmIoctlMagic << 8) | dmVersionCmd)
	dmDevCreateIOCTL  = uintptr((dmIoctlReadWrite << 30) | (dmIoctlSize << 16) | (dmIoctlMagic << 8) | dmDevCreateCmd)
	dmDevSuspendIOCTL = uintptr((dmIoctlReadWrite << 30) | (dmIoctlSize << 16) | (dmIoctlMagic << 8) | dmDevSuspendCmd)
	dmDevStatusIOCTL  = uintptr((dmIoctlReadWrite << 30) | (dmIoctlSize << 16) | (dmIoctlMagic << 8) | dmDevStatusCmd)
	dmTableLoadIOCTL  = uintptr((dmIoctlReadWrite << 30) | (dmIoctlSize << 16) | (dmIoctlMagic << 8) | dmTableLoadCmd)
)

var consoleMu sync.Mutex

var initrdModuleOrder = []string{
	"dm-bufio.ko",
	"dm-verity.ko",
}

type verityMetadata struct {
	hashType       uint32
	dataBlocks     uint64
	dataBlockSize  uint32
	hashBlockSize  uint32
	hashStartBlock uint64
	hashAlgorithm  string
	salt           []byte
}

type dmInfo struct {
	dev         uint64
	flags       uint32
	openCount   int32
	targetCount uint32
}

func main() {
	log.SetFlags(0)
	os.Setenv("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")

	if err := run(); err != nil {
		initrdLogf("fatal: %v", err)
		dumpBlockState()
		for {
			time.Sleep(time.Minute)
		}
	}
}

func run() error {
	if err := mountInitrdFilesystems(); err != nil {
		return err
	}
	initrdLogf("starting %s", programMarker)
	if err := loadInitrdModuleClosure(); err != nil {
		return err
	}

	roothash, err := cmdlineValue("roothash")
	if err != nil || !isHex64(roothash) {
		return errors.New("missing or invalid roothash")
	}
	roothash = strings.ToLower(roothash)
	// systemd-repart convention (see systemd-repart(8) Verity=/VerityMatchKey=,
	// also used by systemd's gpt-auto verity discovery): the data partition's
	// GPT UUID is the first 128 bits of the dm-verity root hash and the hash
	// partition's UUID is the final 128 bits. mkosi.repart/10-root.conf and
	// 11-root-verity.conf build the image this way, so the measured roothash
	// on the kernel cmdline is sufficient to locate both partitions.
	rootHex32, verityHex32 := splitRoothash(roothash)
	rootPartUUID := guidFromHex32(rootHex32)
	verityPartUUID := guidFromHex32(verityHex32)

	initrdLogf("waiting for root PARTUUID %s", rootPartUUID)
	rootDevice, err := findPartUUID(rootPartUUID, 30*time.Second)
	if err != nil {
		return fmt.Errorf("root data partition not found: %w", err)
	}
	initrdLogf("waiting for verity PARTUUID %s", verityPartUUID)
	verityDevice, err := findPartUUID(verityPartUUID, 30*time.Second)
	if err != nil {
		return fmt.Errorf("root verity partition not found: %w", err)
	}

	initrdLogf("reading measured root metadata")
	metadata, err := readVerityMetadata(verityDevice)
	if err != nil {
		return err
	}

	rootDevNumber, err := blockDevNumber(rootDevice)
	if err != nil {
		return err
	}
	verityDevNumber, err := blockDevNumber(verityDevice)
	if err != nil {
		return err
	}
	verityLengthSectors := metadata.dataBlocks * uint64(metadata.dataBlockSize) / 512
	verityParams := fmt.Sprintf(
		"%d %s %s %d %d %d %d %s %s %s",
		metadata.hashType,
		rootDevNumber,
		verityDevNumber,
		metadata.dataBlockSize,
		metadata.hashBlockSize,
		metadata.dataBlocks,
		metadata.hashStartBlock,
		metadata.hashAlgorithm,
		roothash,
		hex.EncodeToString(metadata.salt),
	)

	initrdLogf("creating measured root")
	info, err := createMeasuredRoot(verityLengthSectors, verityParams)
	if err != nil {
		return err
	}
	initrdLogf("measured root active: dev=%d:%d flags=0x%x targets=%d open=%d",
		unix.Major(info.dev),
		unix.Minor(info.dev),
		info.flags,
		info.targetCount,
		info.openCount,
	)
	initrdLogf("measured root node ready")
	if !isBlockDevice(dmRootNode) {
		return fmt.Errorf("%s was not created", dmRootNode)
	}

	if err := os.MkdirAll("/sysroot", 0755); err != nil {
		return err
	}
	initrdLogf("mounting measured root")
	if err := unix.Mount(dmRootNode, "/sysroot", "ext4", unix.MS_RDONLY, ""); err != nil {
		return fmt.Errorf("mounting measured root: %w", err)
	}
	initrdLogf("measured root mounted")

	return switchRoot("/sysroot", boot.InitBinary)
}

func loadInitrdModuleClosure() error {
	mode, err := initrdModuleMode()
	if err != nil {
		return err
	}
	switch mode {
	case initrdModuleManifestMode:
		return loadInitrdModules(initrdModuleManifest)
	case initrdModuleBuiltinMode:
		initrdLogf("skipping bounded initrd module loader: dm targets are built into the kernel")
		return nil
	default:
		return fmt.Errorf("unsupported %s=%q", initrdModuleModeKey, mode)
	}
}

func initrdModuleMode() (string, error) {
	data, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		return "", err
	}
	return initrdModuleModeFrom(string(data))
}

func initrdModuleModeFrom(cmdline string) (string, error) {
	mode, err := cmdlineValueFrom(cmdline, initrdModuleModeKey)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return initrdModuleBuiltinMode, nil
	case err != nil:
		return "", fmt.Errorf("reading %s: %w", initrdModuleModeKey, err)
	case mode == initrdModuleManifestMode || mode == initrdModuleBuiltinMode:
		return mode, nil
	}
	return "", fmt.Errorf("unsupported %s=%q", initrdModuleModeKey, mode)
}

func mountInitrdFilesystems() error {
	mounts := []struct {
		source string
		target string
		fstype string
		flags  uintptr
		data   string
	}{
		{"devtmpfs", "/dev", "devtmpfs", unix.MS_NOSUID, "mode=0755"},
		{"proc", "/proc", "proc", 0, ""},
		{"sysfs", "/sys", "sysfs", 0, ""},
		{"tmpfs", "/run", "tmpfs", unix.MS_NOSUID | unix.MS_NODEV, "mode=0755"},
		{"configfs", "/sys/kernel/config", "configfs", 0, ""},
	}
	for _, mount := range mounts {
		if err := mountIfNeeded(mount.source, mount.target, mount.fstype, mount.flags, mount.data); err != nil {
			return err
		}
	}
	initrdLogf("mounted initrd filesystems")
	return nil
}

func mountIfNeeded(source, target, fstype string, flags uintptr, data string) error {
	if isMountPoint(target) {
		return nil
	}
	if err := os.MkdirAll(target, 0755); err != nil {
		return err
	}
	if err := unix.Mount(source, target, fstype, flags, data); err != nil {
		if errors.Is(err, unix.EBUSY) {
			return nil
		}
		return fmt.Errorf("mount %s on %s: %w", fstype, target, err)
	}
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

func loadInitrdModules(manifestPath string) error {
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("reading bounded initrd module manifest: %w", err)
	}
	modules, err := parseModuleManifest(data)
	if err != nil {
		return err
	}
	initrdLogf("bounded initrd module loader reading %d entries", len(modules))
	for _, modulePath := range modules {
		if err := loadKernelModule(modulePath); err != nil {
			if errors.Is(err, unix.EEXIST) {
				initrdLogf("initrd module already loaded: %s", filepath.Base(modulePath))
				continue
			}
			return err
		}
		initrdLogf("initrd module loaded: %s", filepath.Base(modulePath))
	}
	return nil
}

func parseModuleManifest(data []byte) ([]string, error) {
	var modules []string
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for lineNo := 1; scanner.Scan(); lineNo++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if len(modules) >= maxInitrdModules {
			return nil, fmt.Errorf("bounded initrd module manifest exceeds %d entries", maxInitrdModules)
		}
		expected := initrdModuleOrder[len(modules)]
		if !strings.HasPrefix(line, "/usr/lib/modules/") ||
			filepath.Clean(line) != line ||
			!strings.Contains(line, "/kernel/drivers/md/") ||
			filepath.Base(line) != expected {
			return nil, fmt.Errorf("invalid initrd module path on line %d: %s", lineNo, line)
		}
		modules = append(modules, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(modules) != len(initrdModuleOrder) {
		return nil, fmt.Errorf("bounded initrd module manifest has %d entries, want %d", len(modules), len(initrdModuleOrder))
	}
	return modules, nil
}

func loadKernelModule(modulePath string) error {
	file, err := os.Open(modulePath)
	if err != nil {
		return fmt.Errorf("opening initrd module %s: %w", modulePath, err)
	}
	defer file.Close()
	if err := unix.FinitModule(int(file.Fd()), "", 0); err != nil {
		return fmt.Errorf("loading initrd module %s: %w", filepath.Base(modulePath), err)
	}
	return nil
}

func cmdlineValue(name string) (string, error) {
	data, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		return "", err
	}
	return cmdlineValueFrom(string(data), name)
}

func cmdlineValueFrom(cmdline, name string) (string, error) {
	prefix := name + "="
	for _, field := range strings.Fields(cmdline) {
		if strings.HasPrefix(field, prefix) {
			return strings.TrimPrefix(field, prefix), nil
		}
	}
	return "", os.ErrNotExist
}

func isHex64(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, char := range value {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') && (char < 'A' || char > 'F') {
			return false
		}
	}
	return true
}

func splitRoothash(roothash string) (string, string) {
	return roothash[:32], roothash[32:]
}

func guidFromHex32(value string) string {
	value = strings.ToLower(value)
	return fmt.Sprintf("%s-%s-%s-%s-%s", value[:8], value[8:12], value[12:16], value[16:20], value[20:])
}

func findPartUUID(want string, timeout time.Duration) (string, error) {
	want = strings.ToLower(want)
	deadline := time.Now().Add(timeout)
	for {
		matches, _ := filepath.Glob("/sys/block/*/*/uevent")
		for _, path := range matches {
			fields, err := readUevent(path)
			if err != nil {
				continue
			}
			if fields["DEVTYPE"] != "partition" {
				continue
			}
			if strings.ToLower(fields["PARTUUID"]) != want {
				continue
			}
			dev := "/dev/" + fields["DEVNAME"]
			if isBlockDevice(dev) {
				return dev, nil
			}
		}
		if time.Now().After(deadline) {
			return "", os.ErrNotExist
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func readUevent(path string) (map[string]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	fields := make(map[string]string)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		key, value, ok := strings.Cut(scanner.Text(), "=")
		if ok {
			fields[key] = value
		}
	}
	return fields, scanner.Err()
}

func isBlockDevice(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeDevice != 0 && info.Mode()&os.ModeCharDevice == 0
}

func isCharDevice(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

func createMeasuredRoot(lengthSectors uint64, params string) (dmInfo, error) {
	if err := ensureDeviceMapperControl(); err != nil {
		return dmInfo{}, err
	}

	control, err := os.OpenFile(dmControlNode, os.O_RDWR, 0)
	if err != nil {
		return dmInfo{}, fmt.Errorf("opening %s: %w", dmControlNode, err)
	}
	defer control.Close()

	if err := dmVersion(control); err != nil {
		return dmInfo{}, err
	}
	if _, err := dmDeviceCreate(control, dmName); err != nil {
		return dmInfo{}, err
	}
	initrdLogf("measured root device created")
	if err := dmTableLoad(control, dmName, lengthSectors, "verity", params); err != nil {
		return dmInfo{}, err
	}
	initrdLogf("measured root table loaded")
	if err := dmDeviceResume(control, dmName); err != nil {
		return dmInfo{}, err
	}
	initrdLogf("measured root resumed")

	info, err := dmDeviceStatus(control, dmName)
	if err != nil {
		return dmInfo{}, err
	}
	if info.flags&dmActivePresentFlag == 0 {
		return dmInfo{}, errors.New("measured root device has no active table")
	}
	if info.flags&dmReadOnlyFlag == 0 {
		return dmInfo{}, errors.New("measured root device is not read-only")
	}
	if err := ensureBlockNode(dmRootNode, info.dev); err != nil {
		return dmInfo{}, err
	}
	return info, nil
}

func ensureDeviceMapperControl() error {
	if isCharDevice(dmControlNode) {
		return nil
	}
	deadline := time.Now().Add(5 * time.Second)
	var lastErr error
	for {
		major, minor, err := readMajorMinor("/sys/class/misc/device-mapper/dev")
		if err == nil {
			if err := os.MkdirAll(filepath.Dir(dmControlNode), 0755); err != nil {
				return err
			}
			dev := int(unix.Mkdev(major, minor))
			if err := unix.Mknod(dmControlNode, unix.S_IFCHR|0600, dev); err != nil && !errors.Is(err, unix.EEXIST) {
				return fmt.Errorf("creating %s: %w", dmControlNode, err)
			}
			if isCharDevice(dmControlNode) {
				return nil
			}
			lastErr = fmt.Errorf("%s was created but is not a character device", dmControlNode)
		} else {
			lastErr = err
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("device-mapper control node not ready: %w", lastErr)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func ensureBlockNode(path string, dev uint64) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	if info, err := os.Stat(path); err == nil {
		if info.Mode()&os.ModeDevice != 0 && info.Mode()&os.ModeCharDevice == 0 {
			if stat, ok := info.Sys().(*syscall.Stat_t); ok &&
				unix.Major(stat.Rdev) == unix.Major(dev) &&
				unix.Minor(stat.Rdev) == unix.Minor(dev) {
				return nil
			}
		}
		if err := os.Remove(path); err != nil {
			return fmt.Errorf("removing stale %s: %w", path, err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := unix.Mknod(path, unix.S_IFBLK|0600, int(dev)); err != nil {
		return fmt.Errorf("creating %s: %w", path, err)
	}
	return nil
}

func readMajorMinor(path string) (uint32, uint32, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, 0, err
	}
	majorText, minorText, ok := strings.Cut(strings.TrimSpace(string(data)), ":")
	if !ok {
		return 0, 0, fmt.Errorf("invalid device number in %s", path)
	}
	var major, minor uint32
	if _, err := fmt.Sscanf(majorText, "%d", &major); err != nil {
		return 0, 0, fmt.Errorf("invalid major in %s: %w", path, err)
	}
	if _, err := fmt.Sscanf(minorText, "%d", &minor); err != nil {
		return 0, 0, fmt.Errorf("invalid minor in %s: %w", path, err)
	}
	return major, minor, nil
}

func dmVersion(control *os.File) error {
	buf := dmBaseBuffer(dmIoctlSize, "")
	if err := dmIoctl(control, dmVersionIOCTL, buf); err != nil {
		return fmt.Errorf("device-mapper version ioctl failed: %w", err)
	}
	versionMajor := binary.LittleEndian.Uint32(buf[0:4])
	if versionMajor != dmVersionMajor {
		return fmt.Errorf("unsupported device-mapper ioctl major version %d", versionMajor)
	}
	initrdLogf("device-mapper ioctl version %d.%d.%d",
		versionMajor,
		binary.LittleEndian.Uint32(buf[4:8]),
		binary.LittleEndian.Uint32(buf[8:12]),
	)
	return nil
}

func dmDeviceCreate(control *os.File, name string) (dmInfo, error) {
	buf := dmBaseBuffer(16*1024, name)
	dmSetFlags(buf, dmReadOnlyFlag|dmExistsFlag)
	if err := dmIoctl(control, dmDevCreateIOCTL, buf); err != nil {
		return dmInfo{}, fmt.Errorf("device-mapper create %s failed: %w", name, err)
	}
	return dmInfoFromBuffer(buf), nil
}

func dmTableLoad(control *os.File, name string, lengthSectors uint64, targetType, params string) error {
	buf, err := dmTableLoadBuffer(name, lengthSectors, targetType, params)
	if err != nil {
		return err
	}
	if err := dmIoctl(control, dmTableLoadIOCTL, buf); err != nil {
		return fmt.Errorf("device-mapper table load %s failed: %w", name, err)
	}
	return nil
}

func dmDeviceResume(control *os.File, name string) error {
	buf := dmBaseBuffer(2*1024, name)
	dmSetFlags(buf, dmReadOnlyFlag|dmExistsFlag)
	if err := dmIoctl(control, dmDevSuspendIOCTL, buf); err != nil {
		return fmt.Errorf("device-mapper resume %s failed: %w", name, err)
	}
	return nil
}

func dmDeviceStatus(control *os.File, name string) (dmInfo, error) {
	buf := dmBaseBuffer(16*1024, name)
	dmSetFlags(buf, dmExistsFlag)
	if err := dmIoctl(control, dmDevStatusIOCTL, buf); err != nil {
		return dmInfo{}, fmt.Errorf("device-mapper status %s failed: %w", name, err)
	}
	info := dmInfoFromBuffer(buf)
	if info.flags&dmExistsFlag == 0 {
		return dmInfo{}, fmt.Errorf("device-mapper device %s does not exist", name)
	}
	return info, nil
}

func dmBaseBuffer(size int, name string) []byte {
	if size < dmIoctlSize {
		size = dmIoctlSize
	}
	buf := make([]byte, size)
	binary.LittleEndian.PutUint32(buf[0:4], dmVersionMajor)
	binary.LittleEndian.PutUint32(buf[4:8], dmVersionMinor)
	binary.LittleEndian.PutUint32(buf[8:12], dmVersionPatch)
	binary.LittleEndian.PutUint32(buf[12:16], uint32(len(buf)))
	binary.LittleEndian.PutUint32(buf[16:20], dmIoctlDataStart)
	putCString(buf[dmNameOffset:dmNameOffset+128], name)
	return buf
}

func dmTableLoadBuffer(name string, lengthSectors uint64, targetType, params string) ([]byte, error) {
	if targetType == "" || len(targetType) >= 16 {
		return nil, fmt.Errorf("invalid device-mapper target type %q", targetType)
	}
	targetSize := align(dmTargetSpecSize+len(params)+1, dmTargetSpecAlign)
	buf := dmBaseBuffer(dmIoctlSize+targetSize, name)
	dmSetFlags(buf, dmReadOnlyFlag|dmExistsFlag)
	binary.LittleEndian.PutUint32(buf[20:24], 1)

	spec := buf[dmIoctlSize : dmIoctlSize+dmTargetSpecSize]
	binary.LittleEndian.PutUint64(spec[0:8], 0)
	binary.LittleEndian.PutUint64(spec[8:16], lengthSectors)
	binary.LittleEndian.PutUint32(spec[20:24], uint32(targetSize))
	putCString(spec[24:40], targetType)
	putCString(buf[dmIoctlSize+dmTargetSpecSize:dmIoctlSize+targetSize], params)
	return buf, nil
}

func dmSetFlags(buf []byte, flags uint32) {
	binary.LittleEndian.PutUint32(buf[28:32], flags)
}

func dmInfoFromBuffer(buf []byte) dmInfo {
	return dmInfo{
		dev:         binary.LittleEndian.Uint64(buf[dmDevOffset : dmDevOffset+8]),
		flags:       binary.LittleEndian.Uint32(buf[28:32]),
		openCount:   int32(binary.LittleEndian.Uint32(buf[24:28])),
		targetCount: binary.LittleEndian.Uint32(buf[20:24]),
	}
}

func dmIoctl(control *os.File, request uintptr, buf []byte) error {
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, control.Fd(), request, uintptr(unsafe.Pointer(&buf[0])))
	if errno != 0 {
		return errno
	}
	return nil
}

func putCString(dst []byte, value string) {
	copy(dst, value)
	if len(value) < len(dst) {
		dst[len(value)] = 0
	}
}

func align(value, alignment int) int {
	return (value + alignment - 1) &^ (alignment - 1)
}

func readVerityMetadata(device string) (verityMetadata, error) {
	file, err := os.Open(device)
	if err != nil {
		return verityMetadata{}, fmt.Errorf("opening verity metadata device %s: %w", device, err)
	}
	defer file.Close()

	superblock := make([]byte, veritySuperblockLen)
	if _, err := file.ReadAt(superblock, 0); err != nil {
		return verityMetadata{}, fmt.Errorf("reading verity superblock: %w", err)
	}
	return parseVeritySuperblock(superblock)
}

func parseVeritySuperblock(superblock []byte) (verityMetadata, error) {
	if len(superblock) < veritySuperblockLen {
		return verityMetadata{}, fmt.Errorf("verity superblock too short: %d bytes", len(superblock))
	}
	if string(superblock[:8]) != "verity\x00\x00" {
		return verityMetadata{}, errors.New("verity signature not found")
	}

	version := binary.LittleEndian.Uint32(superblock[8:12])
	if version != 1 {
		return verityMetadata{}, fmt.Errorf("unsupported verity version %d", version)
	}

	hashType := binary.LittleEndian.Uint32(superblock[12:16])
	if hashType > 1 {
		return verityMetadata{}, fmt.Errorf("unsupported verity hash type %d", hashType)
	}

	algorithmBytes := superblock[32:64]
	algorithmLen := 0
	for algorithmLen < len(algorithmBytes) && algorithmBytes[algorithmLen] != 0 {
		algorithmLen++
	}
	algorithm := string(algorithmBytes[:algorithmLen])
	if algorithm == "" {
		return verityMetadata{}, errors.New("verity hash algorithm is empty")
	}
	for _, char := range algorithm {
		if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' && char != '_' {
			return verityMetadata{}, fmt.Errorf("unsupported verity hash algorithm %q", algorithm)
		}
	}

	dataBlockSize := binary.LittleEndian.Uint32(superblock[64:68])
	hashBlockSize := binary.LittleEndian.Uint32(superblock[68:72])
	if !validVerityBlockSize(dataBlockSize) {
		return verityMetadata{}, fmt.Errorf("unsupported verity data block size %d", dataBlockSize)
	}
	if !validVerityBlockSize(hashBlockSize) {
		return verityMetadata{}, fmt.Errorf("unsupported verity hash block size %d", hashBlockSize)
	}

	dataBlocks := binary.LittleEndian.Uint64(superblock[72:80])
	if dataBlocks == 0 {
		return verityMetadata{}, errors.New("verity data block count is zero")
	}

	saltSize := binary.LittleEndian.Uint16(superblock[80:82])
	if saltSize > 256 {
		return verityMetadata{}, fmt.Errorf("verity salt size %d exceeds superblock salt capacity", saltSize)
	}
	salt := append([]byte(nil), superblock[88:88+int(saltSize)]...)

	hashStartBlock := (uint64(veritySuperblockLen) + uint64(hashBlockSize) - 1) / uint64(hashBlockSize)
	if hashStartBlock == 0 {
		return verityMetadata{}, errors.New("verity hash start block is zero")
	}

	return verityMetadata{
		hashType:       hashType,
		dataBlocks:     dataBlocks,
		dataBlockSize:  dataBlockSize,
		hashBlockSize:  hashBlockSize,
		hashStartBlock: hashStartBlock,
		hashAlgorithm:  algorithm,
		salt:           salt,
	}, nil
}

func validVerityBlockSize(size uint32) bool {
	return size >= 512 && size <= 512*1024 && size%512 == 0 && size&(size-1) == 0
}

func blockDevNumber(device string) (string, error) {
	name := strings.TrimPrefix(device, "/dev/")
	data, err := os.ReadFile(filepath.Join("/sys/class/block", name, "dev"))
	if err != nil {
		return "", fmt.Errorf("missing sysfs device number for %s: %w", device, err)
	}
	return strings.TrimSpace(string(data)), nil
}

func switchRoot(newRoot, initPath string) error {
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		initrdLogf("warning: making mounts private: %v", err)
	}
	for _, dir := range []string{"dev", "proc", "sys", "run"} {
		source := "/" + dir
		target := filepath.Join(newRoot, dir)
		initrdLogf("moving %s into measured root", source)
		if err := os.MkdirAll(target, 0755); err != nil {
			return err
		}
		if err := unix.Mount(source, target, "", unix.MS_MOVE, ""); err != nil {
			return fmt.Errorf("moving %s into measured root: %w", source, err)
		}
		initrdLogf("moved %s into measured root", source)
	}

	initrdLogf("switching to tinfoil-init")
	if err := unix.Chdir(newRoot); err != nil {
		return err
	}
	if err := unix.Mount(newRoot, "/", "", unix.MS_MOVE, ""); err != nil {
		return fmt.Errorf("moving measured root to /: %w", err)
	}
	if err := unix.Chroot("."); err != nil {
		return err
	}
	if err := unix.Chdir("/"); err != nil {
		return err
	}
	return unix.Exec(initPath, []string{initPath}, os.Environ())
}

func dumpBlockState() {
	initrdLogf("block state dump follows")
	paths, _ := filepath.Glob("/sys/block/*/uevent")
	partitions, _ := filepath.Glob("/sys/block/*/*/uevent")
	paths = append(paths, partitions...)
	for _, path := range paths {
		fields, err := readUevent(path)
		if err != nil {
			continue
		}
		summary := strings.TrimPrefix(path, "/sys/") + ":"
		for _, key := range []string{"DEVNAME", "DEVTYPE", "PARTUUID", "PARTNAME", "MAJOR", "MINOR"} {
			if value := fields[key]; value != "" {
				summary += " " + key + "=" + value
			}
		}
		initrdLogf("%s", summary)
	}
}

func initrdLogf(format string, args ...any) {
	message := fmt.Sprintf(format, args...)
	consoleMu.Lock()
	defer consoleMu.Unlock()
	log.Print("tinfoil-initrd: " + message)
	for _, path := range []string{"/dev/kmsg", "/dev/ttyS0", "/dev/console"} {
		file, err := os.OpenFile(path, os.O_WRONLY|syscall.O_NONBLOCK, 0)
		if err != nil {
			continue
		}
		if path == "/dev/kmsg" {
			_, _ = fmt.Fprintf(file, "<6>tinfoil-initrd: %s\n", message)
		} else {
			_, _ = fmt.Fprintf(file, "tinfoil-initrd: %s\n", message)
		}
		_ = file.Close()
	}
}
