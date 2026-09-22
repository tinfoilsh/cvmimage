// Package volume activates encrypted storage volumes for boot and runtime unlocks.
package volume

import (
	"bytes"
	"context"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"

	"golang.org/x/crypto/argon2"
	"golang.org/x/sys/unix"

	"tinfoil/internal/boot"
	"tinfoil/internal/device"
	"tinfoil/internal/devicemapper"
	"tinfoil/internal/runtimeconfig"
)

const (
	controlRoot     = boot.VolumeControlDir
	dataRoot        = boot.VolumeDataDir
	mapperRoot      = "tinfoil-volume-"
	upperSuffix     = ".upper"
	workSuffix      = ".work"
	integritySuffix = "-integrity"

	VersionHKDF   byte = 1
	VersionArgon2 byte = 2
	tableKeyInfo       = "tinfoil volume table key v1"

	maxOwner       = 65534
	maxOverlays    = 8
	MinKeyBytes    = 16
	blankProbeSize = 1 << 20

	headerMagic    = "tinfoil-volume-1"
	headerBytes    = 4096
	argonTime      = 3
	argonMemoryKiB = 256 << 10
	argonThreads   = 4
)

var (
	namePattern  = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
	modelPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	// A source may hold slashes; every segment begins with a non-dot to keep out
	// `.`/`..`, and the class keeps out the comma and colon that would inject
	// extra layers or mount options.
	sourcePattern = regexp.MustCompile(`^[A-Za-z0-9_-][A-Za-z0-9._-]*(/[A-Za-z0-9_-][A-Za-z0-9._-]*)*$`)
)

type Spec struct {
	runtimeconfig.VolumeSpec
	Models int
	Index  int
}

type mountState struct {
	id     uint64
	device uint64
}

type volume struct {
	Spec
	control  *os.File
	source   *os.File
	unlocked bool
}

type diskHeader struct {
	Magic   [len(headerMagic)]byte
	Time    uint32
	Memory  uint32
	Threads uint8
	_       [3]byte
	Salt    [32]byte
}

func (parsed Spec) Validate() error {
	if parsed.Models < 0 {
		return fmt.Errorf("invalid model disk count %d", parsed.Models)
	}
	if parsed.Index < 0 {
		return fmt.Errorf("invalid storage volume index %d", parsed.Index)
	}
	if !namePattern.MatchString(parsed.Name) {
		return fmt.Errorf("invalid storage volume name %q", parsed.Name)
	}
	if parsed.Owner < 0 || parsed.Owner > maxOwner {
		return fmt.Errorf("invalid storage volume owner %d", parsed.Owner)
	}
	if err := device.StorageSlots(parsed.Models, parsed.Index+1); err != nil {
		return err
	}
	// Re-checked here, not trusted from the caller: these strings are spliced
	// into mount options and one names a directory this worker creates on the
	// volume. The same paths are measured in tinfoil-config; this is the second
	// gate.
	if len(parsed.Overlays) > maxOverlays {
		return fmt.Errorf("too many overlays: %d", len(parsed.Overlays))
	}
	if len(parsed.Overlays) > 0 && !parsed.Exec {
		return errors.New("overlays require an executable volume")
	}
	for _, spec := range parsed.Overlays {
		if !modelPattern.MatchString(spec.Model) || !sourcePattern.MatchString(spec.Source) || !namePattern.MatchString(spec.Target) {
			return fmt.Errorf("invalid overlay %q", spec.Model)
		}
	}
	return nil
}

// Mount opens a volume during boot. A blank disk is initialized; any other
// disk must open with this key.
func Mount(ctx context.Context, spec Spec, key []byte) error {
	if len(key) < MinKeyBytes {
		return fmt.Errorf("key is %d bytes, want at least %d", len(key), MinKeyBytes)
	}
	instance, err := openVolume(spec)
	if err != nil {
		return err
	}
	defer instance.closeDevices()
	mounted, err := instance.prepare()
	if err != nil || mounted {
		return err
	}
	blank, err := blockDeviceBlank(instance.source)
	if err != nil {
		return err
	}
	return instance.activate(ctx, key, blank, VersionArgon2)
}

func openVolume(parsed Spec) (*volume, error) {
	if err := parsed.Validate(); err != nil {
		return nil, err
	}
	control, err := devicemapper.OpenControl()
	if err != nil {
		return nil, err
	}
	if _, err := devicemapper.CheckVersion(control); err != nil {
		control.Close()
		return nil, err
	}
	sourcePath, err := device.StorageDisk(parsed.Models, parsed.Index)
	if err != nil {
		control.Close()
		return nil, err
	}
	source, err := devicemapper.OpenBlockDevice(sourcePath)
	if err != nil {
		control.Close()
		return nil, err
	}
	return &volume{Spec: parsed, control: control, source: source}, nil
}

func (w *volume) closeDevices() {
	if w.source != nil {
		_ = w.source.Close()
		w.source = nil
	}
	if w.control != nil {
		_ = w.control.Close()
		w.control = nil
	}
}

func (w *volume) controlDir() string {
	return filepath.Join(controlRoot, w.Name)
}

func (w *volume) dataPath() string {
	return filepath.Join(dataRoot, w.Name)
}

func (w *volume) mapperName() string {
	return mapperRoot + w.Name
}

func (w *volume) mapperNode() string {
	return devicemapper.MapperNode(w.mapperName())
}

func (w *volume) integrityName() string {
	return w.mapperName() + integritySuffix
}

func (w *volume) prepare() (bool, error) {
	if err := os.MkdirAll(w.controlDir(), 0o700); err != nil {
		return false, err
	}
	if err := os.Chmod(w.controlDir(), 0o711); err != nil {
		return false, err
	}
	if err := os.MkdirAll(w.dataPath(), 0o755); err != nil {
		return false, err
	}
	target, parent, err := mountStates(w.dataPath())
	if err != nil {
		return false, err
	}
	if target.id == parent.id {
		if err := unix.Mount(w.dataPath(), w.dataPath(), "", unix.MS_BIND, ""); err != nil {
			return false, err
		}
	}
	if err := unix.Mount("", w.dataPath(), "", unix.MS_SHARED, ""); err != nil {
		return false, err
	}
	return w.inspect()
}

func (w *volume) inspect() (bool, error) {
	target, parent, err := mountStates(w.dataPath())
	if err != nil {
		return false, err
	}
	info, mapped, err := devicemapper.Lookup(w.control, w.mapperName())
	if err != nil {
		return false, err
	}
	if mapped && target.id != parent.id && target.device == info.Dev {
		if !info.Active() || info.ReadOnly() || info.TargetCount != 1 {
			return false, fmt.Errorf("mapping %s has unexpected state", w.mapperName())
		}
		return true, nil
	}
	if err := w.removeUnopened(w.mapperName()); err != nil {
		return false, err
	}
	if err := w.removeUnopened(w.integrityName()); err != nil {
		return false, err
	}
	if target.id != parent.id && target.device != parent.device {
		return false, fmt.Errorf("unexpected mount at %s", w.dataPath())
	}
	return false, nil
}

func (w *volume) removeUnopened(name string) error {
	info, mapped, err := devicemapper.Lookup(w.control, name)
	if err != nil || !mapped {
		return err
	}
	if info.OpenCount > 0 {
		return fmt.Errorf("mapping %s is open without its mount", name)
	}
	return devicemapper.Remove(w.control, name)
}

func (w *volume) activate(ctx context.Context, key []byte, initialize bool, version byte) (result error) {
	// Zeroing is safe only over a header and superblock this call wrote and before mkfs has finished behind it.
	rollback := initialize
	defer func() {
		if result != nil && rollback {
			result = errors.Join(result, w.writeStart(make([]byte, blankProbeSize)))
		}
	}()
	tableKey, reserved, err := w.tableKey(key, initialize, version)
	if err != nil {
		return err
	}
	defer clear(tableKey)
	if err := devicemapper.ActivateIntegrity(w.control, w.source, w.integrityName(), reserved, initialize); err != nil {
		return err
	}
	defer func() {
		if result != nil {
			result = errors.Join(result, devicemapper.Remove(w.control, w.integrityName()))
		}
	}()
	tags, err := devicemapper.OpenBlockDevice(devicemapper.MapperNode(w.integrityName()))
	if err != nil {
		return err
	}
	defer tags.Close()
	mappedDevice, err := devicemapper.ActivateWritableCrypt(w.control, tags, w.mapperName(), tableKey)
	if err != nil {
		return err
	}
	mounted := false
	defer func() {
		if result == nil {
			return
		}
		if mounted {
			result = errors.Join(result, unix.Unmount(w.dataPath(), 0))
		}
		result = errors.Join(result, devicemapper.Remove(w.control, w.mapperName()))
	}()
	if initialize {
		if err := prepareFormat(w.mapperNode(), w.Owner); err != nil {
			return fmt.Errorf("preparing volume for format: %w", err)
		}
		command := exec.CommandContext(ctx, boot.VolumeWorkerBinary, FormatMode, w.mapperNode(), strconv.Itoa(w.Owner))
		command.Env = []string{}
		command.Stdout = io.Discard
		var diagnostics bytes.Buffer
		command.Stderr = &diagnostics
		if err := command.Run(); err != nil {
			return fmt.Errorf("formatting volume: %w: %s", err, bytes.TrimSpace(diagnostics.Bytes()))
		}
		rollback = false
	}
	flags := uintptr(unix.MS_NODEV | unix.MS_NOSUID)
	if !w.Exec {
		flags |= unix.MS_NOEXEC
	}
	if err := unix.Mount(w.mapperNode(), w.dataPath(), "ext4", flags, "errors=remount-ro"); err != nil {
		return fmt.Errorf("mounting volume: %w", err)
	}
	mounted = true
	target, _, err := mountStates(w.dataPath())
	if err != nil {
		return err
	}
	if target.device != mappedDevice {
		return fmt.Errorf("mounted unexpected device %d:%d", unix.Major(target.device), unix.Minor(target.device))
	}
	merged, err := w.mountOverlays()
	defer func() {
		if result == nil {
			return
		}
		for index := len(merged) - 1; index >= 0; index-- {
			result = errors.Join(result, unix.Unmount(merged[index], 0))
		}
	}()
	return err
}

// mountOverlays reports every layer it merged, on failure as well, because the
// caller unwinds them.
func (w *volume) mountOverlays() ([]string, error) {
	merged := make([]string, 0, len(w.Overlays))
	for _, spec := range w.Overlays {
		mountPoint, err := w.overlay(spec)
		if mountPoint != "" {
			merged = append(merged, mountPoint)
		}
		if err != nil {
			return merged, err
		}
	}
	return merged, nil
}

func (w *volume) overlay(spec runtimeconfig.VolumeOverlay) (string, error) {
	lower := filepath.Join(boot.PrivateModelsDir, spec.Model, spec.Source)
	// sourcePattern keeps the spec inside the pack, but a symlink in the pack
	// would still resolve the lower layer out of it, so the path has to be real.
	resolved, err := filepath.EvalSymlinks(lower)
	if err != nil {
		return "", err
	}
	if resolved != lower {
		return "", fmt.Errorf("overlay source %s is not a real path in the pack", lower)
	}
	mountPoint := filepath.Join(w.dataPath(), spec.Target)
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
	if !w.Exec {
		flags |= unix.MS_NOEXEC
	}
	options := "lowerdir=" + lower + ",upperdir=" + upper + ",workdir=" + work
	if err := unix.Mount("overlay", mountPoint, "overlay", flags, options); err != nil {
		return "", fmt.Errorf("merging %s into %s: %w", lower, mountPoint, err)
	}
	// overlayfs performs every upper-layer operation as the mounter, so upper and work stay ours.
	if err := os.Chown(mountPoint, w.Owner, w.Owner); err != nil {
		return mountPoint, err
	}
	return mountPoint, nil
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

func (w *volume) tableKey(key []byte, initialize bool, version byte) ([]byte, int64, error) {
	switch version {
	case VersionHKDF:
		tableKey, err := hkdf.Key(sha256.New, key, nil, tableKeyInfo, devicemapper.AuthenticatedKeyBytes)
		return tableKey, 0, err
	case VersionArgon2:
		h, err := w.header(initialize)
		if err != nil {
			return nil, 0, err
		}
		return argon2.IDKey(key, h.Salt[:], h.Time, h.Memory, h.Threads, devicemapper.AuthenticatedKeyBytes), headerBytes, nil
	}
	return nil, 0, fmt.Errorf("unsupported volume format %d", version)
}

func (w *volume) header(initialize bool) (diskHeader, error) {
	var h diskHeader
	if initialize {
		copy(h.Magic[:], headerMagic)
		h.Time, h.Memory, h.Threads = argonTime, argonMemoryKiB, argonThreads
		rand.Read(h.Salt[:])
		raw, err := binary.Append(nil, binary.LittleEndian, h)
		if err != nil {
			return h, err
		}
		return h, w.writeStart(raw)
	}
	if err := unix.IoctlSetInt(int(w.source.Fd()), unix.BLKFLSBUF, 0); err != nil {
		return h, fmt.Errorf("invalidating the stale block cache: %w", err)
	}
	raw := make([]byte, binary.Size(h))
	if _, err := w.source.ReadAt(raw, 0); err != nil {
		return h, fmt.Errorf("reading volume header: %w", err)
	}
	if _, err := binary.Decode(raw, binary.LittleEndian, &h); err != nil {
		return h, err
	}
	if string(h.Magic[:]) != headerMagic {
		return h, errors.New("storage volume carries no header")
	}
	if h.Time != argonTime || h.Memory != argonMemoryKiB || h.Threads != argonThreads {
		return h, fmt.Errorf("unsupported key derivation parameters %d/%d/%d", h.Time, h.Memory, h.Threads)
	}
	return h, nil
}

func blockDeviceBlank(source *os.File) (bool, error) {
	if source == nil {
		return false, errors.New("storage volume is unavailable")
	}
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

func (w *volume) writeStart(data []byte) error {
	raw, err := os.OpenFile(w.source.Name(), os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer raw.Close()
	if _, err := raw.WriteAt(data, 0); err != nil {
		return err
	}
	return raw.Sync()
}
