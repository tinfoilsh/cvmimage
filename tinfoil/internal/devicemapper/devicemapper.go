// Package devicemapper provides the minimal device-mapper ioctl operations
// needed to create and activate a read-only mapping.
package devicemapper

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
	if targetType == "" || len(targetType) >= 16 || strings.IndexByte(targetType, 0) >= 0 {
		return nil, fmt.Errorf("invalid device-mapper target type %q", targetType)
	}
	if strings.IndexByte(params, 0) >= 0 {
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
	putCString(buf[ioctlSize+targetSpecSize:ioctlSize+targetSize], params)
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
	if len(dst) == 0 {
		return
	}
	n := copy(dst[:len(dst)-1], value)
	dst[n] = 0
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
