package main

import (
	"crypto/hkdf"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"tinfoil/internal/bootstate"
	"tinfoil/internal/device"
	"tinfoil/internal/devicemapper"
	"tinfoil/internal/runtimeconfig"
)

const (
	mapperRoot = "tinfoil-volume-"
	mkfsPath   = "/usr/sbin/mkfs.ext4"
	formatMode = "--format"
	selfPath   = "/proc/self/exe"

	upperSuffix     = ".upper"
	workSuffix      = ".work"
	integritySuffix = "-integrity"

	// A request carries one key, but the table needs a cipher key and a MAC key.
	tableKeyInfo = "tinfoil volume table key v1"

	// The extend is one write of a whole digest to this file. It is TDX's
	// alone; SEV-SNP guests have no such register and the path is absent.
	rtmr3Path = "/sys/devices/virtual/misc/tdx_guest/measurements/rtmr3:sha384"

	blankProbeSize = 1 << 20
)

var namePattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)

// volume is the workspace: the one storage disk the measured config declares,
// which sits after the model disks in the fixed PCI layout.
type volume struct {
	spec   runtimeconfig.VolumeSpec
	models int
}

type mountState struct {
	id     uint64
	device uint64
}

func (v *volume) mapperName() string    { return mapperRoot + v.spec.Name }
func (v *volume) mapperNode() string    { return devicemapper.MapperNode(v.mapperName()) }
func (v *volume) integrityName() string { return v.mapperName() + integritySuffix }

// open spends the key on the volume. A blank device is formatted for this
// owner and any other is unlocked; dm-crypt accepts any key, so the mount is
// the only proof this one opened the volume, and a wrong key leaves nothing
// behind but the permit, still worth retrying.
func (v *volume) open(key, seal []byte) (result error) {
	target, parent, err := mountStates(workspace)
	if err != nil {
		return err
	}
	if target.id != parent.id {
		return errors.New("workspace is already open")
	}
	control, err := devicemapper.OpenControl()
	if err != nil {
		return err
	}
	defer control.Close()
	if _, err := devicemapper.CheckVersion(control); err != nil {
		return err
	}
	sourcePath, err := device.StorageDisk(v.models, 0)
	if err != nil {
		return err
	}
	source, err := devicemapper.OpenBlockDevice(sourcePath)
	if err != nil {
		return err
	}
	defer source.Close()
	blank, err := blockDeviceBlank(source)
	if err != nil {
		return err
	}
	tableKey, err := hkdf.Key(sha256.New, key, nil, tableKeyInfo, devicemapper.AuthenticatedKeyBytes)
	if err != nil {
		return err
	}
	defer clear(tableKey)
	if err := devicemapper.ActivateIntegrity(control, source, v.integrityName(), blank); err != nil {
		return err
	}
	defer func() {
		if result != nil {
			result = errors.Join(result, devicemapper.Remove(control, v.integrityName()))
		}
	}()
	tags, err := devicemapper.OpenBlockDevice(devicemapper.MapperNode(v.integrityName()))
	if err != nil {
		return err
	}
	defer tags.Close()
	mappedDevice, err := devicemapper.ActivateWritableCrypt(control, tags, v.mapperName(), tableKey)
	if err != nil {
		return err
	}
	mounted := false
	defer func() {
		if result == nil {
			return
		}
		if mounted {
			result = errors.Join(result, unix.Unmount(workspace, 0))
		}
		result = errors.Join(result, devicemapper.Remove(control, v.mapperName()))
	}()
	if blank {
		command := exec.Command(selfPath, formatMode, v.mapperNode())
		command.Env = []string{}
		command.Stdout = io.Discard
		command.Stderr = io.Discard
		if err := command.Run(); err != nil {
			return fmt.Errorf("formatting volume: %w", err)
		}
	}
	flags := uintptr(unix.MS_NODEV | unix.MS_NOSUID)
	if !v.spec.Exec {
		flags |= unix.MS_NOEXEC
	}
	if err := unix.Mount(v.mapperNode(), workspace, "ext4", flags, "errors=remount-ro"); err != nil {
		return fmt.Errorf("mounting volume: %w", err)
	}
	mounted = true
	target, _, err = mountStates(workspace)
	if err != nil {
		return err
	}
	if target.device != mappedDevice {
		return fmt.Errorf("mounted unexpected device %d:%d", unix.Major(target.device), unix.Minor(target.device))
	}
	// Here rather than before the mapping, because only the mount proves the
	// key was right, and a wrong key must leave the register untouched.
	if err := extendSeal(seal); err != nil {
		return err
	}
	// Last, so a later failure never leaves the rollback above unable to unmount
	// a volume with an overlay still on top of it.
	return v.mountOverlays()
}

// extendSeal marks this boot with what the caller sealed it to. The write is
// the extend -- hardware replaces the register with the hash of its old value
// and these bytes -- so a marked boot cannot be returned to an unmarked one
// without a reboot. Where the guest has no such register there is nothing to
// extend and nothing in the attestation to read it from, which is why the mark
// is a client-side check against the report rather than this program's word.
func extendSeal(digest []byte) error {
	file, err := os.OpenFile(rtmr3Path, os.O_WRONLY, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("opening the seal register: %w", err)
	}
	if _, err := file.Write(digest); err != nil {
		file.Close()
		return fmt.Errorf("extending the seal register: %w", err)
	}
	return file.Close()
}

func (v *volume) mountOverlays() (result error) {
	merged := make([]string, 0, len(v.spec.Overlays))
	defer func() {
		if result == nil {
			return
		}
		for index := len(merged) - 1; index >= 0; index-- {
			result = errors.Join(result, unix.Unmount(merged[index], 0))
		}
	}()
	for _, spec := range v.spec.Overlays {
		mountPoint, err := v.overlay(spec)
		if err != nil {
			return err
		}
		merged = append(merged, mountPoint)
	}
	return nil
}

// overlay merges one model pack into the volume, entirely from the measured
// config: source inside the pack is the read-only lower, target inside the
// volume is where the merged tree appears.
func (v *volume) overlay(spec runtimeconfig.VolumeOverlay) (string, error) {
	lower := filepath.Join(bootstate.PrivateModelsDir, spec.Model, spec.Source)
	// The config keeps the spec inside the pack, but a symlink in the pack
	// would still resolve the lower layer out of it, so the path has to be real.
	resolved, err := filepath.EvalSymlinks(lower)
	if err != nil {
		return "", err
	}
	if resolved != lower {
		return "", fmt.Errorf("overlay source %s is not a real path in the pack", lower)
	}
	mountPoint := filepath.Join(workspace, spec.Target)
	upper, work := mountPoint+upperSuffix, mountPoint+workSuffix
	for _, directory := range []string{mountPoint, upper, work} {
		if err := os.Mkdir(directory, 0o755); err != nil && !errors.Is(err, os.ErrExist) {
			return "", err
		}
		// A pre-existing entry is tolerated because the volume persists, but a
		// symlink here would send the mount, or the upper writes, off the volume.
		info, err := os.Lstat(directory)
		if err != nil {
			return "", err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return "", fmt.Errorf("overlay path %s is not a directory", directory)
		}
	}
	flags := uintptr(unix.MS_NODEV | unix.MS_NOSUID)
	if !v.spec.Exec {
		flags |= unix.MS_NOEXEC
	}
	options := "lowerdir=" + lower + ",upperdir=" + upper + ",workdir=" + work
	if err := unix.Mount("overlay", mountPoint, "overlay", flags, options); err != nil {
		return "", fmt.Errorf("merging %s into %s: %w", lower, mountPoint, err)
	}
	return mountPoint, nil
}

// runFormatter is the re-executed child that runs mkfs with every capability
// dropped, so a hostile device is parsed by a process that can do nothing else.
func runFormatter(args []string) error {
	if len(args) != 3 {
		return errors.New("invalid formatter invocation")
	}
	base := filepath.Base(args[2])
	name := strings.TrimPrefix(base, mapperRoot)
	if filepath.Dir(args[2]) != "/dev/mapper" || base == name || !namePattern.MatchString(name) {
		return errors.New("invalid formatter device")
	}
	runtime.LockOSThread()
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var empty [2]unix.CapUserData
	if err := unix.Capset(&header, &empty[0]); err != nil {
		return err
	}
	var current [2]unix.CapUserData
	if err := unix.Capget(&header, &current[0]); err != nil {
		return err
	}
	for _, data := range current {
		if data.Effective != 0 || data.Permitted != 0 || data.Inheritable != 0 {
			return errors.New("formatter retained capabilities")
		}
	}
	// Nothing is left to first use: dm-integrity holds no tag for a block that was
	// never written, so a lazy table or journal reads back as an I/O error.
	return syscall.Exec(mkfsPath, []string{mkfsPath, "-F", "-q", "-E", "lazy_itable_init=0,lazy_journal_init=0", args[2]}, []string{})
}

func mountStates(path string) (mountState, mountState, error) {
	target, err := readMountState(path)
	if err != nil {
		return mountState{}, mountState{}, err
	}
	parent, err := readMountState(filepath.Dir(path))
	if err != nil {
		return mountState{}, mountState{}, err
	}
	return target, parent, nil
}

func readMountState(path string) (mountState, error) {
	var info unix.Statx_t
	mask := unix.STATX_BASIC_STATS | unix.STATX_MNT_ID
	if err := unix.Statx(unix.AT_FDCWD, path, unix.AT_SYMLINK_NOFOLLOW, mask, &info); err != nil {
		return mountState{}, err
	}
	if info.Mask&unix.STATX_MNT_ID == 0 {
		return mountState{}, errors.New("kernel omitted mount ID")
	}
	return mountState{
		id:     info.Mnt_id,
		device: unix.Mkdev(info.Dev_major, info.Dev_minor),
	}, nil
}

func blockDeviceBlank(source *os.File) (bool, error) {
	// This device is attached to the VM after the guest has already booted, and
	// the kernel read sector 0 of it while enumerating it -- against the empty
	// backing that stood there until the attach. That page is still in the
	// block device's cache and reads as zeros, so a probe that trusted it could
	// call a workspace that has been in use blank, and the caller treats blank
	// as permission to reformat. BLKFLSBUF drops the cache, which is what makes
	// the read below see the volume that is actually attached now.
	if err := unix.IoctlSetInt(int(source.Fd()), unix.BLKFLSBUF, 0); err != nil {
		return false, fmt.Errorf("invalidating the stale block cache: %w", err)
	}
	buffer := make([]byte, blankProbeSize)
	defer clear(buffer)
	n, err := source.ReadAt(buffer, 0)
	if err != nil && !errors.Is(err, io.EOF) {
		return false, err
	}
	if n == 0 {
		return false, errors.New("storage volume is empty")
	}
	for _, value := range buffer[:n] {
		if value != 0 {
			return false, nil
		}
	}
	return true, nil
}
