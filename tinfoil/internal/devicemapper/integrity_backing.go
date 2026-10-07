package devicemapper

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

type integrityBacking struct {
	header *os.File
	source *os.File
}

// newIntegrityBacking replaces only sectors 0..7. The tmpfs file remains
// writable by the trusted guest kernel for normal superblock writes; its
// contents and size are inaccessible to the VMM. Neither the file nor its
// mount has a pathname once this function returns. The loop device retains
// the file after the worker exits. noswap is required, not best-effort.
func newIntegrityBacking(control *os.File, name, rawDevice string, sectors uint64, header []byte) (_ *integrityBacking, result error) {
	if len(header) != integrityHeaderBytes {
		return nil, errors.New("invalid integrity header snapshot length")
	}
	memory, err := privateHeaderFile(header)
	if err != nil {
		return nil, err
	}
	defer func() {
		if result != nil {
			memory.Close()
		}
	}()
	loop, err := attachHeaderLoop(memory)
	if err != nil {
		return nil, err
	}
	defer loop.Close() // autoclear once the linear table also releases it
	loopDevice, loopSectors, err := blockDeviceInfo(loop)
	if err != nil {
		return nil, err
	}
	if loopSectors != integrityHeaderSectors {
		return nil, errors.New("unexpected header loop capacity")
	}
	buf, err := integrityBackingTable(name, loopDevice, rawDevice, sectors)
	if err != nil {
		return nil, err
	}
	if _, err := create(control, name, 0); err != nil {
		return nil, err
	}
	defer func() {
		if result != nil {
			result = errors.Join(result, Remove(control, name))
		}
	}()
	if err := ioctl(control, tableLoadIOCTL, buf, 2); err != nil {
		return nil, err
	}
	if err := resume(control, name, 0); err != nil {
		return nil, err
	}
	info, err := Status(control, name)
	if err != nil {
		return nil, err
	}
	if !info.Active() || info.ReadOnly() || info.TargetCount != 2 {
		return nil, errors.New("unexpected integrity backing state")
	}
	if err := EnsureBlockNode(MapperNode(name), info.Dev); err != nil {
		return nil, err
	}
	source, err := OpenBlockDevice(MapperNode(name))
	if err != nil {
		return nil, err
	}
	return &integrityBacking{header: memory, source: source}, nil
}

func privateHeaderFile(header []byte) (_ *os.File, result error) {
	if len(header) != integrityHeaderBytes {
		return nil, errors.New("invalid private header size")
	}
	// /run is guest-owned. A fresh, root-only mount avoids inheriting a tmpfs
	// that could swap to untrusted storage. An anonymous inode survives the
	// detached mount only as long as our file/loop references do.
	directory, err := os.MkdirTemp("/run", "tinfoil-integrity-")
	if err != nil {
		return nil, err
	}
	defer os.Remove(directory)
	if err := unix.Mount("tmpfs", directory, "tmpfs", unix.MS_NODEV|unix.MS_NOSUID|unix.MS_NOEXEC, fmt.Sprintf("mode=0700,size=%d,noswap", integrityHeaderBytes)); err != nil {
		return nil, fmt.Errorf("mounting unswappable integrity header: %w", err)
	}
	var file *os.File
	defer func() {
		result = errors.Join(result, unix.Unmount(directory, unix.MNT_DETACH))
		if result != nil && file != nil {
			result = errors.Join(result, file.Close())
		}
	}()
	fd, err := unix.Open(directory, unix.O_TMPFILE|unix.O_RDWR|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, err
	}
	file = os.NewFile(uintptr(fd), "integrity-header")
	if err := file.Truncate(integrityHeaderBytes); err != nil {
		return nil, err
	}
	if _, err := file.WriteAt(header, 0); err != nil {
		return nil, err
	}
	return file, nil
}

func attachHeaderLoop(file *os.File) (*os.File, error) {
	major, minor, err := readMajorMinor("/sys/class/misc/loop-control/dev")
	if err != nil {
		return nil, err
	}
	const controlPath = "/dev/loop-control"
	if err := ensureLoopNode(controlPath, unix.S_IFCHR, unix.Mkdev(major, minor)); err != nil {
		return nil, err
	}
	fd, err := unix.Open(controlPath, unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	var controlStat unix.Stat_t
	if err := unix.Fstat(fd, &controlStat); err != nil {
		return nil, err
	}
	if controlStat.Mode&unix.S_IFMT != unix.S_IFCHR || controlStat.Rdev != unix.Mkdev(major, minor) {
		return nil, errors.New("opened loop control does not match its sysfs identity")
	}
	// Another volume worker can claim a free loop between GET_FREE and
	// CONFIGURE. Only retry EBUSY; never take over an existing attachment.
	for attempt := 0; attempt < 16; attempt++ {
		number, err := unix.IoctlRetInt(fd, unix.LOOP_CTL_GET_FREE)
		if err != nil {
			return nil, err
		}
		path := fmt.Sprintf("/dev/loop%d", number)
		loopMajor, loopMinor, err := readMajorMinor(filepath.Join("/sys/class/block", fmt.Sprintf("loop%d", number), "dev"))
		if err != nil {
			return nil, err
		}
		dev := unix.Mkdev(loopMajor, loopMinor)
		if err := ensureLoopNode(path, unix.S_IFBLK, dev); err != nil {
			return nil, err
		}
		loopFD, err := unix.Open(path, unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			return nil, err
		}
		var stat unix.Stat_t
		if err := unix.Fstat(loopFD, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFBLK || stat.Rdev != dev {
			unix.Close(loopFD)
			return nil, fmt.Errorf("unexpected loop device %s", path)
		}
		config := unix.LoopConfig{Fd: uint32(file.Fd()), Size: dmSectorSizeBytes, Info: unix.LoopInfo64{Sizelimit: integrityHeaderBytes, Flags: unix.LO_FLAGS_AUTOCLEAR}}
		err = unix.IoctlLoopConfigure(loopFD, &config)
		if err == nil {
			return os.NewFile(uintptr(loopFD), path), nil
		}
		unix.Close(loopFD)
		if !errors.Is(err, unix.EBUSY) {
			return nil, fmt.Errorf("attaching private integrity header: %w", err)
		}
	}
	return nil, errors.New("no free loop device for integrity header")
}

// Repair only device nodes. Callers also verify the identity of the opened FD.
func ensureLoopNode(path string, mode uint32, dev uint64) error {
	if info, err := os.Lstat(path); err == nil {
		if deviceNodeMatches(path, mode == unix.S_IFCHR, dev) {
			return nil
		}
		if info.Mode()&os.ModeDevice == 0 {
			return fmt.Errorf("refusing to replace non-device loop node %s", path)
		}
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := unix.Mknod(path, mode|0600, int(dev)); err != nil && !errors.Is(err, unix.EEXIST) {
		return err
	}
	return nil
}

func validDeviceNumber(device string) bool {
	major, minor, ok := strings.Cut(device, ":")
	if !ok {
		return false
	}
	a, errA := strconv.ParseUint(major, 10, 32)
	b, errB := strconv.ParseUint(minor, 10, 32)
	return errA == nil && errB == nil && fmt.Sprintf("%d:%d", a, b) == device
}

// integrityBackingTable is deliberately limited to this exact two-target
// layout. All offsets are constants; the raw superblock is unreachable through
// the composite device. No caller-supplied device-mapper target type is accepted.
func integrityBackingTable(name, headerDevice, rawDevice string, sectors uint64) ([]byte, error) {
	if err := validateName(name); err != nil {
		return nil, err
	}
	if !validDeviceNumber(headerDevice) || !validDeviceNumber(rawDevice) || headerDevice == rawDevice ||
		sectors <= integrityHeaderSectors || sectors > (1<<63-1)/dmSectorSizeBytes {
		return nil, errors.New("invalid integrity backing devices or size")
	}
	params := [2]string{headerDevice + " 0", fmt.Sprintf("%s %d", rawDevice, integrityHeaderSectors)}
	sizes := [2]int{align(targetSpecSize+len(params[0])+1, targetSpecAlign), align(targetSpecSize+len(params[1])+1, targetSpecAlign)}
	buf, err := baseBuffer(ioctlSize+sizes[0]+sizes[1], name)
	if err != nil {
		return nil, err
	}
	setFlags(buf, existsFlag)
	binary.LittleEndian.PutUint32(buf[20:24], 2)
	position := ioctlSize
	for index, param := range params {
		spec := buf[position : position+sizes[index]]
		start, length := uint64(0), uint64(integrityHeaderSectors)
		if index == 1 {
			start, length = integrityHeaderSectors, sectors-integrityHeaderSectors
		}
		binary.LittleEndian.PutUint64(spec[0:8], start)
		binary.LittleEndian.PutUint64(spec[8:16], length)
		binary.LittleEndian.PutUint32(spec[20:24], uint32(sizes[index]))
		putCString(spec[24:40], "linear")
		putCString(spec[targetSpecSize:], param)
		position += sizes[index]
	}
	return buf, nil
}
