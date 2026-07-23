// Package devicemapper provides the minimal device-mapper ioctl operations
// needed to create and activate a read-only mapping.
package devicemapper

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	ControlNode = "/dev/mapper/control"

	controlDevicePath = "/sys/class/misc/device-mapper/dev"
	ioctlSize         = 312
	ioctlDataStart    = ioctlSize
	targetSpecSize    = 40
	nameOffset        = 48
	devOffset         = 40
	targetSpecAlign   = 8
	maxNameLen        = 127

	versionMajor = 4
	versionMinor = 0
	versionPatch = 0

	versionCmd    = 0
	devCreateCmd  = 3
	devRemoveCmd  = 4
	devSuspendCmd = 6
	devStatusCmd  = 7
	tableLoadCmd  = 9

	readOnlyFlag      = 1 << 0
	existsFlag        = 0x00000004
	activePresentFlag = 1 << 5
	ioctlMagic        = 0xfd
	ioctlReadWrite    = 3
)

const (
	versionIOCTL    = uintptr((ioctlReadWrite << 30) | (ioctlSize << 16) | (ioctlMagic << 8) | versionCmd)
	devCreateIOCTL  = uintptr((ioctlReadWrite << 30) | (ioctlSize << 16) | (ioctlMagic << 8) | devCreateCmd)
	devRemoveIOCTL  = uintptr((ioctlReadWrite << 30) | (ioctlSize << 16) | (ioctlMagic << 8) | devRemoveCmd)
	devSuspendIOCTL = uintptr((ioctlReadWrite << 30) | (ioctlSize << 16) | (ioctlMagic << 8) | devSuspendCmd)
	devStatusIOCTL  = uintptr((ioctlReadWrite << 30) | (ioctlSize << 16) | (ioctlMagic << 8) | devStatusCmd)
	tableLoadIOCTL  = uintptr((ioctlReadWrite << 30) | (ioctlSize << 16) | (ioctlMagic << 8) | tableLoadCmd)
)

// Version is the device-mapper ioctl protocol version reported by the kernel.
type Version struct {
	Major uint32
	Minor uint32
	Patch uint32
}

// Info is the device state returned by create and status ioctls.
type Info struct {
	Dev         uint64
	Flags       uint32
	OpenCount   int32
	TargetCount uint32
}

// Active reports whether the device has an active table.
func (info Info) Active() bool {
	return info.Flags&activePresentFlag != 0
}

// ReadOnly reports whether the device is read-only.
func (info Info) ReadOnly() bool {
	return info.Flags&readOnlyFlag != 0
}

// OpenControl ensures the control node exists and opens it for ioctls.
func OpenControl() (*os.File, error) {
	if err := EnsureControlNode(); err != nil {
		return nil, err
	}
	control, err := os.OpenFile(ControlNode, os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", ControlNode, err)
	}
	return control, nil
}

// EnsureControlNode creates /dev/mapper/control from its sysfs device number.
func EnsureControlNode() error {
	deadline := time.Now().Add(5 * time.Second)
	var lastErr error
	for {
		major, minor, err := readMajorMinor(controlDevicePath)
		if err == nil {
			dev := unix.Mkdev(major, minor)
			if deviceNodeMatches(ControlNode, true, dev) {
				return nil
			}
			if err := os.MkdirAll(filepath.Dir(ControlNode), 0755); err != nil {
				return err
			}
			if err := removeStaleNode(ControlNode); err != nil {
				return fmt.Errorf("removing stale %s: %w", ControlNode, err)
			}
			if err := unix.Mknod(ControlNode, unix.S_IFCHR|0600, int(dev)); err != nil && !errors.Is(err, unix.EEXIST) {
				return fmt.Errorf("creating %s: %w", ControlNode, err)
			}
			if deviceNodeMatches(ControlNode, true, dev) {
				return nil
			}
			lastErr = fmt.Errorf("%s does not match device-mapper device %d:%d", ControlNode, major, minor)
		} else {
			lastErr = err
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("device-mapper control node not ready: %w", lastErr)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// EnsureBlockNode creates path for the block device returned by device-mapper.
func EnsureBlockNode(path string, dev uint64) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	if deviceNodeMatches(path, false, dev) {
		return nil
	}
	if err := removeStaleNode(path); err != nil {
		return fmt.Errorf("removing stale %s: %w", path, err)
	}
	if err := unix.Mknod(path, unix.S_IFBLK|0600, int(dev)); err != nil {
		return fmt.Errorf("creating %s: %w", path, err)
	}
	if !deviceNodeMatches(path, false, dev) {
		return fmt.Errorf("%s does not match device-mapper block device %d:%d", path, unix.Major(dev), unix.Minor(dev))
	}
	return nil
}

// CheckVersion verifies and returns the kernel's ioctl protocol version.
func CheckVersion(control *os.File) (Version, error) {
	buf := baseBuffer(ioctlSize, "")
	if err := ioctl(control, versionIOCTL, buf); err != nil {
		return Version{}, fmt.Errorf("device-mapper version ioctl failed: %w", err)
	}
	version := Version{
		Major: binary.LittleEndian.Uint32(buf[0:4]),
		Minor: binary.LittleEndian.Uint32(buf[4:8]),
		Patch: binary.LittleEndian.Uint32(buf[8:12]),
	}
	if version.Major != versionMajor {
		return Version{}, fmt.Errorf("unsupported device-mapper ioctl major version %d", version.Major)
	}
	return version, nil
}

// CreateReadOnly creates an empty read-only device-mapper device.
func CreateReadOnly(control *os.File, name string) (Info, error) {
	if err := validateName(name); err != nil {
		return Info{}, err
	}
	buf := baseBuffer(16*1024, name)
	setFlags(buf, readOnlyFlag|existsFlag)
	if err := ioctl(control, devCreateIOCTL, buf); err != nil {
		return Info{}, fmt.Errorf("device-mapper create %s failed: %w", name, err)
	}
	return infoFromBuffer(buf), nil
}

// LoadReadOnlyVerityTable loads one read-only verity target covering
// lengthSectors. The target type is fixed so callers cannot select a broader
// device-mapper surface.
func LoadReadOnlyVerityTable(control *os.File, name string, lengthSectors uint64, params string) error {
	if err := validateName(name); err != nil {
		return err
	}
	buf, err := tableLoadBuffer(name, lengthSectors, "verity", params)
	if err != nil {
		return err
	}
	if err := ioctl(control, tableLoadIOCTL, buf); err != nil {
		return fmt.Errorf("device-mapper table load %s failed: %w", name, err)
	}
	return nil
}

// LoadReadOnlyCryptTable loads one read-only crypt target covering
// lengthSectors. Parameters are bytes so embedded key material can be erased
// immediately after the ioctl completes.
func LoadReadOnlyCryptTable(control *os.File, name string, lengthSectors uint64, params []byte) error {
	if err := validateName(name); err != nil {
		return err
	}
	buf, err := tableLoadBufferBytes(name, lengthSectors, "crypt", params)
	if err != nil {
		return err
	}
	defer zeroBytes(buf)
	if err := ioctl(control, tableLoadIOCTL, buf); err != nil {
		return fmt.Errorf("device-mapper table load %s failed: %w", name, err)
	}
	return nil
}

// ResumeReadOnly activates a loaded read-only table.
func ResumeReadOnly(control *os.File, name string) error {
	if err := validateName(name); err != nil {
		return err
	}
	buf := baseBuffer(2*1024, name)
	setFlags(buf, readOnlyFlag|existsFlag)
	if err := ioctl(control, devSuspendIOCTL, buf); err != nil {
		return fmt.Errorf("device-mapper resume %s failed: %w", name, err)
	}
	return nil
}

// Status returns the current device state.
func Status(control *os.File, name string) (Info, error) {
	if err := validateName(name); err != nil {
		return Info{}, err
	}
	buf := baseBuffer(16*1024, name)
	setFlags(buf, existsFlag)
	if err := ioctl(control, devStatusIOCTL, buf); err != nil {
		return Info{}, fmt.Errorf("device-mapper status %s failed: %w", name, err)
	}
	info := infoFromBuffer(buf)
	if info.Flags&existsFlag == 0 {
		return Info{}, fmt.Errorf("device-mapper device %s does not exist", name)
	}
	return info, nil
}

// Remove deletes a device-mapper device and its userspace block node.
func Remove(control *os.File, name string) error {
	if err := validateName(name); err != nil {
		return err
	}
	buf := baseBuffer(ioctlSize, name)
	setFlags(buf, existsFlag)
	if err := ioctl(control, devRemoveIOCTL, buf); err != nil {
		return fmt.Errorf("device-mapper remove %s failed: %w", name, err)
	}
	if err := os.Remove(MapperNode(name)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("removing mapper node %s: %w", MapperNode(name), err)
	}
	return nil
}

// MapperNode returns the fixed block-node path for a mapping.
func MapperNode(name string) string {
	return filepath.Join("/dev/mapper", name)
}

// BlockDeviceNumber returns the kernel major:minor identity for a direct block
// device. Symlinks and non-block files are rejected.
func BlockDeviceNumber(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", fmt.Errorf("stat block device %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeDevice == 0 || info.Mode()&os.ModeCharDevice != 0 {
		return "", fmt.Errorf("%s is not a direct block device", path)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", fmt.Errorf("%s has unexpected stat data", path)
	}
	return fmt.Sprintf("%d:%d", unix.Major(stat.Rdev), unix.Minor(stat.Rdev)), nil
}

// BlockDeviceSectors returns a block device size in 512-byte sectors.
func BlockDeviceSectors(path string) (uint64, error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, fmt.Errorf("opening block device %s: %w", path, err)
	}
	defer file.Close()
	var size uint64
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, file.Fd(), unix.BLKGETSIZE64, uintptr(unsafe.Pointer(&size)))
	if errno != 0 {
		return 0, fmt.Errorf("reading block device size %s: %w", path, errno)
	}
	if size == 0 || size%512 != 0 {
		return 0, fmt.Errorf("invalid block device size %d for %s", size, path)
	}
	return size / 512, nil
}

// CryptTable builds the fixed dm-crypt parameters used for encrypted model
// volumes. The returned buffer contains key material and must be erased after
// table loading.
func CryptTable(deviceNumber, cipher string, key []byte, sectorSize uint32, lengthSectors uint64) ([]byte, error) {
	if deviceNumber == "" || strings.IndexByte(deviceNumber, 0) >= 0 || strings.ContainsAny(deviceNumber, " \t\r\n") {
		return nil, fmt.Errorf("invalid dm-crypt device number %q", deviceNumber)
	}
	if cipher == "" || len(cipher) > 127 || strings.IndexFunc(cipher, func(char rune) bool { return char <= ' ' || char == 0x7f }) >= 0 {
		return nil, fmt.Errorf("invalid dm-crypt cipher %q", cipher)
	}
	if len(key) != 64 {
		return nil, fmt.Errorf("invalid dm-crypt key length %d bytes", len(key))
	}
	if sectorSize < 512 || sectorSize > 4096 || sectorSize%512 != 0 || sectorSize&(sectorSize-1) != 0 {
		return nil, fmt.Errorf("unsupported dm-crypt sector size %d", sectorSize)
	}
	if lengthSectors == 0 || lengthSectors%(uint64(sectorSize)/512) != 0 {
		return nil, fmt.Errorf("dm-crypt length %d sectors is not aligned to sector size %d", lengthSectors, sectorSize)
	}

	params := make([]byte, 0, len(cipher)+hex.EncodedLen(len(key))+len(deviceNumber)+32)
	params = append(params, cipher...)
	params = append(params, ' ')
	params = hex.AppendEncode(params, key)
	params = append(params, " 0 "...)
	params = append(params, deviceNumber...)
	params = append(params, " 0 1 sector_size:"...)
	params = strconv.AppendUint(params, uint64(sectorSize), 10)
	return params, nil
}

func validateName(name string) error {
	if name == "" || len(name) > maxNameLen {
		return fmt.Errorf("invalid device-mapper name length for %q", name)
	}
	for _, char := range name {
		if char >= 'a' && char <= 'z' ||
			char >= 'A' && char <= 'Z' ||
			char >= '0' && char <= '9' ||
			strings.ContainsRune("-_.+", char) {
			continue
		}
		return fmt.Errorf("invalid character %q in device-mapper name %q", char, name)
	}
	return nil
}

func baseBuffer(size int, name string) []byte {
	if size < ioctlSize {
		size = ioctlSize
	}
	buf := make([]byte, size)
	binary.LittleEndian.PutUint32(buf[0:4], versionMajor)
	binary.LittleEndian.PutUint32(buf[4:8], versionMinor)
	binary.LittleEndian.PutUint32(buf[8:12], versionPatch)
	binary.LittleEndian.PutUint32(buf[12:16], uint32(len(buf)))
	binary.LittleEndian.PutUint32(buf[16:20], ioctlDataStart)
	putCString(buf[nameOffset:nameOffset+128], name)
	return buf
}

func tableLoadBuffer(name string, lengthSectors uint64, targetType, params string) ([]byte, error) {
	return tableLoadBufferBytes(name, lengthSectors, targetType, []byte(params))
}

func tableLoadBufferBytes(name string, lengthSectors uint64, targetType string, params []byte) ([]byte, error) {
	if targetType == "" || len(targetType) >= 16 || strings.IndexByte(targetType, 0) >= 0 {
		return nil, fmt.Errorf("invalid device-mapper target type %q", targetType)
	}
	if bytesIndexByte(params, 0) >= 0 {
		return nil, fmt.Errorf("device-mapper target parameters contain NUL")
	}
	targetSize := align(targetSpecSize+len(params)+1, targetSpecAlign)
	buf := baseBuffer(ioctlSize+targetSize, name)
	setFlags(buf, readOnlyFlag|existsFlag)
	binary.LittleEndian.PutUint32(buf[20:24], 1)

	spec := buf[ioctlSize : ioctlSize+targetSpecSize]
	binary.LittleEndian.PutUint64(spec[0:8], 0)
	binary.LittleEndian.PutUint64(spec[8:16], lengthSectors)
	binary.LittleEndian.PutUint32(spec[20:24], uint32(targetSize))
	putCString(spec[24:40], targetType)
	putBytesCString(buf[ioctlSize+targetSpecSize:ioctlSize+targetSize], params)
	return buf, nil
}

func setFlags(buf []byte, flags uint32) {
	binary.LittleEndian.PutUint32(buf[28:32], flags)
}

func infoFromBuffer(buf []byte) Info {
	return Info{
		Dev:         binary.LittleEndian.Uint64(buf[devOffset : devOffset+8]),
		Flags:       binary.LittleEndian.Uint32(buf[28:32]),
		OpenCount:   int32(binary.LittleEndian.Uint32(buf[24:28])),
		TargetCount: binary.LittleEndian.Uint32(buf[20:24]),
	}
}

func ioctl(control *os.File, request uintptr, buf []byte) error {
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, control.Fd(), request, uintptr(unsafe.Pointer(&buf[0])))
	if errno != 0 {
		return errno
	}
	return nil
}

func putCString(dst []byte, value string) {
	putBytesCString(dst, []byte(value))
}

func putBytesCString(dst, value []byte) {
	if len(dst) == 0 {
		return
	}
	n := copy(dst[:len(dst)-1], value)
	dst[n] = 0
}

func zeroBytes(buf []byte) {
	for index := range buf {
		buf[index] = 0
	}
}

func bytesIndexByte(buf []byte, value byte) int {
	for index, current := range buf {
		if current == value {
			return index
		}
	}
	return -1
}

func align(value, alignment int) int {
	return (value + alignment - 1) &^ (alignment - 1)
}

func deviceNodeMatches(path string, charDevice bool, dev uint64) bool {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 {
		return false
	}
	if charDevice {
		if info.Mode()&os.ModeCharDevice == 0 {
			return false
		}
	} else if info.Mode()&os.ModeDevice == 0 || info.Mode()&os.ModeCharDevice != 0 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok &&
		unix.Major(stat.Rdev) == unix.Major(dev) &&
		unix.Minor(stat.Rdev) == unix.Minor(dev)
}

func removeStaleNode(path string) error {
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	return os.Remove(path)
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
