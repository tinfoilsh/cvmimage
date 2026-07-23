package main

import (
	"bufio"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"tinfoil/internal/boot"
	"tinfoil/internal/devicemapper"
)

const (
	// systemd-repart derives this salt as
	// HMAC-SHA256(repartSeed, "verity-salt"). mkosi.conf pins the same seed.
	// This is build policy, not secret material.
	repartSeed = "48c56959-5579-5709-85af-f5393936a4d8"
	veritySalt = "d8f43870af05f2fb613c2bb571f911da45cfa46a77e6efeabbdd5ed760ebabde"

	// These are the systemd-repart dm-verity format invariants used by
	// mkosi.repart/10-root.conf and 11-root-verity.conf. A mismatch fails
	// closed because the resulting tree cannot match the measured roothash.
	verityTableVersion   = 1
	verityDataBlockSize  = 4096
	verityHashBlockSize  = 4096
	verityHashAlgorithm  = "sha256"
	verityHashStartBlock = 1

	dmName     = "root"
	dmRootNode = "/dev/mapper/root"
	kmsgInfo   = "<6>"
)

var (
	consoleMu     sync.Mutex
	sysClassBlock = "/sys/class/block"
)

func main() {
	log.SetFlags(0)
	if err := run(); err != nil {
		initrdLogf("fatal: %v", err)
		for {
			time.Sleep(time.Minute)
		}
	}
}

func run() error {
	if err := mountInitrdFilesystems(); err != nil {
		return err
	}

	roothash, err := cmdlineValue("roothash")
	if err != nil || !isHex64(roothash) {
		return errors.New("missing or invalid roothash")
	}
	roothash = strings.ToLower(roothash)

	// systemd-repart assigns the data partition the first 128 bits of the
	// roothash and the hash partition the final 128 bits.
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

	// Partition size comes from kernel sysfs. Every other verity parameter is
	// fixed build policy; no verity superblock bytes are parsed at runtime.
	dataBlocks, err := verityDataBlocks(rootDevice)
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
	verityLengthSectors := dataBlocks * (verityDataBlockSize / 512)
	verityParams := verityTableParams(rootDevNumber, verityDevNumber, dataBlocks, roothash)

	info, err := createMeasuredRoot(verityLengthSectors, verityParams)
	if err != nil {
		return err
	}
	initrdLogf(
		"measured root active: dev=%d:%d flags=0x%x targets=%d",
		unix.Major(info.Dev),
		unix.Minor(info.Dev),
		info.Flags,
		info.TargetCount,
	)
	if !isBlockDevice(dmRootNode) {
		return fmt.Errorf("%s was not created", dmRootNode)
	}

	if err := os.MkdirAll("/sysroot", 0755); err != nil {
		return err
	}
	if err := unix.Mount(dmRootNode, "/sysroot", "ext4", unix.MS_RDONLY, ""); err != nil {
		return fmt.Errorf("mounting measured root: %w", err)
	}
	return switchRoot("/sysroot", boot.InitBinary)
}

func verityTableParams(rootDev, hashDev string, dataBlocks uint64, roothash string) string {
	return fmt.Sprintf(
		"%d %s %s %d %d %d %d %s %s %s",
		verityTableVersion,
		rootDev,
		hashDev,
		verityDataBlockSize,
		verityHashBlockSize,
		dataBlocks,
		verityHashStartBlock,
		verityHashAlgorithm,
		roothash,
		veritySalt,
	)
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
		{"proc", "/proc", "proc", unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC, ""},
		{"sysfs", "/sys", "sysfs", unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC, ""},
		{"tmpfs", "/run", "tmpfs", unix.MS_NOSUID | unix.MS_NODEV, "mode=0755"},
	}
	for _, mount := range mounts {
		if err := mountIfNeeded(mount.source, mount.target, mount.fstype, mount.flags, mount.data); err != nil {
			return err
		}
	}
	return nil
}

func mountIfNeeded(source, target, fstype string, flags uintptr, data string) error {
	if err := os.MkdirAll(target, 0755); err != nil {
		return err
	}
	mounted, err := isMountPoint(target, unix.Statx)
	if err != nil {
		return fmt.Errorf("check mount point %s: %w", target, err)
	}
	if mounted {
		return nil
	}
	if err := unix.Mount(source, target, fstype, flags, data); err != nil {
		if errors.Is(err, unix.EBUSY) {
			return nil
		}
		return fmt.Errorf("mount %s on %s: %w", fstype, target, err)
	}
	return nil
}

type statxFunc func(int, string, int, int, *unix.Statx_t) error

func isMountPoint(target string, statx statxFunc) (bool, error) {
	target = filepath.Clean(target)
	parent := filepath.Dir(target)
	var targetStat, parentStat unix.Statx_t
	if err := statx(unix.AT_FDCWD, target, unix.AT_SYMLINK_NOFOLLOW, unix.STATX_MNT_ID, &targetStat); err != nil {
		return false, err
	}
	if err := statx(unix.AT_FDCWD, parent, unix.AT_SYMLINK_NOFOLLOW, unix.STATX_MNT_ID, &parentStat); err != nil {
		return false, err
	}
	if targetStat.Mask&unix.STATX_MNT_ID == 0 || parentStat.Mask&unix.STATX_MNT_ID == 0 {
		return false, errors.New("kernel omitted STATX_MNT_ID")
	}
	return targetStat.Mnt_id != parentStat.Mnt_id, nil
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
	var value string
	found := false
	for _, field := range strings.Fields(cmdline) {
		candidate, ok := strings.CutPrefix(field, prefix)
		if !ok {
			continue
		}
		if found {
			return "", fmt.Errorf("duplicate kernel command-line parameter %s", name)
		}
		value = candidate
		found = true
	}
	if !found {
		return "", os.ErrNotExist
	}
	return value, nil
}

func isHex64(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, char := range value {
		if (char < '0' || char > '9') &&
			(char < 'a' || char > 'f') &&
			(char < 'A' || char > 'F') {
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
	return fmt.Sprintf(
		"%s-%s-%s-%s-%s",
		value[:8], value[8:12], value[12:16], value[16:20], value[20:],
	)
}

func findPartUUID(want string, timeout time.Duration) (string, error) {
	want = strings.ToLower(want)
	deadline := time.Now().Add(timeout)
	for {
		var matches []string
		uevents, _ := filepath.Glob("/sys/block/*/*/uevent")
		for _, path := range uevents {
			fields, err := readUevent(path)
			if err != nil ||
				fields["DEVTYPE"] != "partition" ||
				strings.ToLower(fields["PARTUUID"]) != want {
				continue
			}
			device := filepath.Join("/dev", fields["DEVNAME"])
			if isBlockDevice(device) {
				matches = append(matches, device)
			}
		}
		switch len(matches) {
		case 1:
			return matches[0], nil
		case 0:
			if time.Now().After(deadline) {
				return "", os.ErrNotExist
			}
			time.Sleep(100 * time.Millisecond)
		default:
			return "", fmt.Errorf("PARTUUID %s is ambiguous", want)
		}
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

func createMeasuredRoot(lengthSectors uint64, params string) (result devicemapper.Info, resultErr error) {
	control, err := devicemapper.OpenControl()
	if err != nil {
		return devicemapper.Info{}, err
	}
	defer control.Close()

	if _, err := devicemapper.CheckVersion(control); err != nil {
		return devicemapper.Info{}, err
	}
	if _, err := devicemapper.CreateReadOnly(control, dmName); err != nil {
		return devicemapper.Info{}, err
	}
	cleanup := true
	defer func() {
		if cleanup {
			if err := devicemapper.Remove(control, dmName); err != nil {
				resultErr = errors.Join(resultErr, fmt.Errorf("cleaning up measured root device: %w", err))
			}
		}
	}()
	if err := devicemapper.LoadReadOnlyVerityTable(control, dmName, lengthSectors, params); err != nil {
		return devicemapper.Info{}, err
	}
	if err := devicemapper.ResumeReadOnly(control, dmName); err != nil {
		return devicemapper.Info{}, err
	}

	info, err := devicemapper.Status(control, dmName)
	if err != nil {
		return devicemapper.Info{}, err
	}
	if !info.Active() {
		return devicemapper.Info{}, errors.New("measured root device has no active table")
	}
	if !info.ReadOnly() {
		return devicemapper.Info{}, errors.New("measured root device is not read-only")
	}
	if err := devicemapper.EnsureBlockNode(dmRootNode, info.Dev); err != nil {
		return devicemapper.Info{}, err
	}
	cleanup = false
	return info, nil
}

// verityDataBlocks derives geometry from the kernel's partition size instead
// of trusting the host-controlled verity superblock.
func verityDataBlocks(dataDevice string) (uint64, error) {
	name := strings.TrimPrefix(dataDevice, "/dev/")
	data, err := os.ReadFile(filepath.Join(sysClassBlock, name, "size"))
	if err != nil {
		return 0, fmt.Errorf("reading data partition size for %s: %w", dataDevice, err)
	}
	sectors, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parsing data partition size: %w", err)
	}
	const sectorsPerDataBlock = verityDataBlockSize / 512
	if sectors == 0 || sectors%sectorsPerDataBlock != 0 {
		return 0, fmt.Errorf(
			"data partition size %d sectors is not a multiple of %d",
			sectors, sectorsPerDataBlock,
		)
	}
	return sectors / sectorsPerDataBlock, nil
}

func blockDevNumber(device string) (string, error) {
	name := strings.TrimPrefix(device, "/dev/")
	data, err := os.ReadFile(filepath.Join(sysClassBlock, name, "dev"))
	if err != nil {
		return "", fmt.Errorf("missing sysfs device number for %s: %w", device, err)
	}
	majorText, minorText, ok := strings.Cut(strings.TrimSpace(string(data)), ":")
	if !ok {
		return "", fmt.Errorf("invalid sysfs device number for %s", device)
	}
	major, majorErr := strconv.ParseUint(majorText, 10, 32)
	minor, minorErr := strconv.ParseUint(minorText, 10, 32)
	if majorErr != nil || minorErr != nil {
		return "", fmt.Errorf("invalid sysfs device number for %s", device)
	}
	return fmt.Sprintf("%d:%d", major, minor), nil
}

func switchRoot(newRoot, initPath string) error {
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return fmt.Errorf("making mounts private before root hand-off: %w", err)
	}
	for _, dir := range []string{"dev", "proc", "sys", "run"} {
		source := "/" + dir
		target := filepath.Join(newRoot, dir)
		if err := os.MkdirAll(target, 0755); err != nil {
			return err
		}
		if err := unix.Mount(source, target, "", unix.MS_MOVE, ""); err != nil {
			return fmt.Errorf("moving %s into measured root: %w", source, err)
		}
	}

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
			_, _ = fmt.Fprintf(file, kmsgInfo+"tinfoil-initrd: %s\n", message)
		} else {
			_, _ = fmt.Fprintf(file, "tinfoil-initrd: %s\n", message)
		}
		_ = file.Close()
	}
}
