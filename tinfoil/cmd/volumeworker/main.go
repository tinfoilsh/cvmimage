package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"tinfoil/internal/boot"
	"tinfoil/internal/device"
	"tinfoil/internal/devicemapper"
)

const (
	controlRoot = boot.VolumeControlDir
	dataRoot    = boot.VolumeDataDir
	socketName  = boot.VolumeSocketName
	mapperRoot  = "tinfoil-volume-"
	mkfsPath    = "/usr/sbin/mkfs.ext4"
	formatMode  = "--format"
	selfPath    = "/proc/self/exe"

	upperSuffix     = ".upper"
	workSuffix      = ".work"
	integritySuffix = "-integrity"

	// A request carries one key, but the table needs a cipher key and a MAC key.
	tableKeyInfo = "tinfoil volume table key v1"
	// tinfoil-cli's sealFor derives the same identity from the same key.
	sealKeyInfo = "tinfoil seal identity v1"

	// The extend is one write of a whole digest to this file. It is TDX's
	// alone; SEV-SNP guests have no such register and the path is absent.
	rtmr3Path = "/sys/devices/virtual/misc/tdx_guest/measurements/rtmr3:sha384"

	maxOwner        = 65534
	maxOverlays     = 8
	keyBytes        = 64
	maxRequestBytes = 512
	blankProbeSize  = 1 << 20
	requestTimeout  = 5 * time.Second

	opStatus     = "status"
	opUnlock     = "unlock"
	opInitialize = "initialize"

	statusOK       = "ok"
	statusRejected = "rejected"
	statusFailed   = "failed"
	statusLocked   = "locked"
)

var (
	namePattern  = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
	modelPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	// A source may hold slashes; every segment begins with a non-dot to keep out
	// `.`/`..`, and the class keeps out the comma and colon that would inject
	// extra layers or mount options.
	sourcePattern = regexp.MustCompile(`^[A-Za-z0-9_-][A-Za-z0-9._-]*(/[A-Za-z0-9_-][A-Za-z0-9._-]*)*$`)
)

// overlay merges one model pack into this volume, entirely from the measured
// invocation: source inside the pack is the read-only lower, target inside the
// volume is where the merged tree appears.
type overlay struct {
	model  string
	source string
	target string
}

type invocation struct {
	models     int
	index      int
	name       string
	executable bool
	owner      int
	overlays   []overlay
}

type mountState struct {
	id     uint64
	device uint64
}

// request is one JSON object per SOCK_SEQPACKET datagram. The overlay layout is
// measured and reaches the worker through its invocation, so the caller supplies
// only the operation and the unlock key.
type request struct {
	Op  string `json:"op"`
	Key []byte `json:"key,omitempty"`
}

type response struct {
	Status string `json:"status"`
}

type worker struct {
	name       string
	executable bool
	owner      int
	overlays   []overlay
	control    *os.File
	source     *os.File
	unlocked   bool
}

func main() {
	log.SetFlags(0)
	if len(os.Args) > 1 && os.Args[1] == formatMode {
		if err := runFormatter(os.Args); err != nil {
			log.Fatalf("tinfoil-volume-worker: %v", err)
		}
		return
	}
	parsed, err := parseInvocation(os.Args)
	if err != nil {
		log.Fatalf("tinfoil-volume-worker: %v", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, parsed); err != nil && !errors.Is(err, context.Canceled) {
		log.Fatalf("tinfoil-volume-worker: %v", err)
	}
}

func parseInvocation(args []string) (invocation, error) {
	if len(args) == 0 {
		return invocation{}, errors.New("missing argv[0]")
	}
	var parsed invocation
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.IntVar(&parsed.models, "models", 0, "")
	flags.IntVar(&parsed.index, "index", 0, "")
	flags.StringVar(&parsed.name, "name", "", "")
	flags.BoolVar(&parsed.executable, "exec", false, "")
	flags.IntVar(&parsed.owner, "owner", 0, "")
	flags.Func("overlay", "", func(value string) error {
		parts := strings.Split(value, ":")
		if len(parts) != 3 {
			return fmt.Errorf("overlay %q is not model:source:target", value)
		}
		parsed.overlays = append(parsed.overlays, overlay{model: parts[0], source: parts[1], target: parts[2]})
		return nil
	})
	if err := flags.Parse(args[1:]); err != nil {
		return invocation{}, err
	}
	if flags.NArg() != 0 {
		return invocation{}, fmt.Errorf("unexpected arguments: %v", flags.Args())
	}
	if parsed.models < 0 {
		return invocation{}, fmt.Errorf("invalid model disk count %d", parsed.models)
	}
	if parsed.index < 0 {
		return invocation{}, fmt.Errorf("invalid storage volume index %d", parsed.index)
	}
	if !namePattern.MatchString(parsed.name) {
		return invocation{}, fmt.Errorf("invalid storage volume name %q", parsed.name)
	}
	if parsed.owner < 0 || parsed.owner > maxOwner {
		return invocation{}, fmt.Errorf("invalid storage volume owner %d", parsed.owner)
	}
	if err := device.StorageSlots(parsed.models, parsed.index+1); err != nil {
		return invocation{}, err
	}
	// Re-checked here, not trusted from the caller: these strings are spliced
	// into mount options and one names a directory this worker creates on the
	// volume. The same paths are measured in tinfoil-config; this is the second
	// gate.
	if len(parsed.overlays) > maxOverlays {
		return invocation{}, fmt.Errorf("too many overlays: %d", len(parsed.overlays))
	}
	if len(parsed.overlays) > 0 && !parsed.executable {
		return invocation{}, errors.New("overlays require an executable volume")
	}
	for _, spec := range parsed.overlays {
		if !modelPattern.MatchString(spec.model) || !sourcePattern.MatchString(spec.source) || !namePattern.MatchString(spec.target) {
			return invocation{}, fmt.Errorf("invalid overlay %q", spec.model)
		}
	}
	return parsed, nil
}

func run(ctx context.Context, parsed invocation) error {
	instance, err := openWorker(parsed)
	if err != nil {
		return err
	}
	defer instance.closeDevices()

	mounted, err := instance.prepare()
	if err != nil {
		return err
	}
	if mounted {
		return nil
	}

	listener, err := listen(instance.socketPath(), instance.owner)
	if err != nil {
		return err
	}
	defer listener.Close()

	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	for {
		connection, err := listener.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		err = instance.serve(connection)
		if err != nil {
			log.Printf("volume %q request failed: %v", instance.name, err)
		}
		if instance.unlocked {
			return err
		}
	}
}

func openWorker(parsed invocation) (*worker, error) {
	control, err := devicemapper.OpenControl()
	if err != nil {
		return nil, err
	}
	if _, err := devicemapper.CheckVersion(control); err != nil {
		control.Close()
		return nil, err
	}
	sourcePath, err := device.StorageDisk(parsed.models, parsed.index)
	if err != nil {
		control.Close()
		return nil, err
	}
	source, err := devicemapper.OpenBlockDevice(sourcePath)
	if err != nil {
		control.Close()
		return nil, err
	}
	return &worker{
		name:       parsed.name,
		executable: parsed.executable,
		owner:      parsed.owner,
		overlays:   parsed.overlays,
		control:    control,
		source:     source,
	}, nil
}

func (w *worker) closeDevices() {
	if w.source != nil {
		_ = w.source.Close()
		w.source = nil
	}
	if w.control != nil {
		_ = w.control.Close()
		w.control = nil
	}
}

func (w *worker) controlDir() string {
	return filepath.Join(controlRoot, w.name)
}

func (w *worker) socketPath() string {
	return filepath.Join(w.controlDir(), socketName)
}

func (w *worker) dataPath() string {
	return filepath.Join(dataRoot, w.name)
}

func (w *worker) mapperName() string {
	return mapperRoot + w.name
}

func (w *worker) mapperNode() string {
	return devicemapper.MapperNode(w.mapperName())
}

func (w *worker) integrityName() string {
	return w.mapperName() + integritySuffix
}

func (w *worker) prepare() (bool, error) {
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

func (w *worker) inspect() (bool, error) {
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

func (w *worker) removeUnopened(name string) error {
	info, mapped, err := devicemapper.Lookup(w.control, name)
	if err != nil || !mapped {
		return err
	}
	if info.OpenCount > 0 {
		return fmt.Errorf("mapping %s is open without its mount", name)
	}
	return devicemapper.Remove(w.control, name)
}

func (w *worker) serve(connection *net.UnixConn) error {
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(requestTimeout)); err != nil {
		return err
	}
	var packet [maxRequestBytes + 1]byte
	defer clear(packet[:])
	n, err := connection.Read(packet[:])
	if err != nil {
		return err
	}
	status, requestErr := w.handle(packet[:n])
	reply, err := json.Marshal(response{Status: status})
	if err != nil {
		return errors.Join(requestErr, err)
	}
	if _, err := connection.Write(reply); err != nil {
		return errors.Join(requestErr, err)
	}
	return requestErr
}

func (w *worker) handle(packet []byte) (string, error) {
	if len(packet) > maxRequestBytes {
		return statusRejected, errors.New("request is too large")
	}
	var spec request
	defer func() { clear(spec.Key) }()
	decoder := json.NewDecoder(bytes.NewReader(packet))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&spec); err != nil {
		return statusRejected, err
	}
	if spec.Op == opStatus {
		return statusLocked, nil
	}
	if spec.Op != opUnlock && spec.Op != opInitialize {
		return statusRejected, fmt.Errorf("invalid request operation %q", spec.Op)
	}
	if len(spec.Key) != keyBytes {
		return statusRejected, fmt.Errorf("key is %d bytes, want %d", len(spec.Key), keyBytes)
	}
	if spec.Op == opInitialize {
		blank, err := blockDeviceBlank(w.source)
		if err != nil {
			return statusFailed, err
		}
		if !blank {
			return statusRejected, errors.New("storage volume is not blank")
		}
	}
	if err := w.activate(spec); err != nil {
		return statusFailed, err
	}
	w.unlocked = true
	return statusOK, nil
}

func (w *worker) activate(spec request) (result error) {
	tableKey, err := hkdf.Key(sha256.New, spec.Key, nil, tableKeyInfo, devicemapper.AuthenticatedKeyBytes)
	if err != nil {
		return err
	}
	defer clear(tableKey)
	if err := devicemapper.ActivateIntegrity(w.control, w.source, w.integrityName(), spec.Op == opInitialize); err != nil {
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
	if spec.Op == opInitialize {
		command := exec.Command(selfPath, formatMode, w.mapperNode(), strconv.Itoa(w.owner))
		command.Env = []string{}
		command.Stdout = io.Discard
		command.Stderr = io.Discard
		if err := command.Run(); err != nil {
			return fmt.Errorf("formatting volume: %w", err)
		}
	}
	flags := uintptr(unix.MS_NODEV | unix.MS_NOSUID)
	if !w.executable {
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
	if err != nil {
		return err
	}
	defer func() {
		if result == nil {
			return
		}
		for index := len(merged) - 1; index >= 0; index-- {
			result = errors.Join(result, unix.Unmount(merged[index], 0))
		}
	}()
	// Here rather than before the mapping, because dm-crypt accepts any key: the
	// mount is the only proof this one opened the volume, so a wrong key leaves
	// the register untouched and the permit still worth retrying. Last of all
	// because the extend cannot be undone: anything failing after it would leave
	// the next attempt marking this boot a second time.
	seed, err := hkdf.Key(sha256.New, spec.Key, nil, sealKeyInfo, ed25519.SeedSize)
	if err != nil {
		return err
	}
	defer clear(seed)
	private := ed25519.NewKeyFromSeed(seed)
	defer clear(private)
	identity := sha512.Sum384(private.Public().(ed25519.PublicKey))
	return extendSeal(identity[:])
}

// extendSeal marks this boot with the identity of the opening key. The write is
// the extend -- hardware replaces the register with the hash of its old value
// and these bytes -- so a marked boot cannot be returned to an unmarked one
// without a reboot. Where the guest has no such register there is nothing to
// extend and nothing in the attestation to read it from, which is why the mark
// is a client-side check against the report rather than this worker's word.
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

func (w *worker) mountOverlays() (_ []string, result error) {
	merged := make([]string, 0, len(w.overlays))
	defer func() {
		if result == nil {
			return
		}
		for index := len(merged) - 1; index >= 0; index-- {
			result = errors.Join(result, unix.Unmount(merged[index], 0))
		}
	}()
	for _, spec := range w.overlays {
		mountPoint, err := w.overlay(spec)
		if err != nil {
			return nil, err
		}
		merged = append(merged, mountPoint)
	}
	return merged, nil
}

func (w *worker) overlay(spec overlay) (string, error) {
	lower := filepath.Join(boot.PrivateModelsDir, spec.model, spec.source)
	// sourcePattern keeps the spec inside the pack, but a symlink in the pack
	// would still resolve the lower layer out of it, so the path has to be real.
	resolved, err := filepath.EvalSymlinks(lower)
	if err != nil {
		return "", err
	}
	if resolved != lower {
		return "", fmt.Errorf("overlay source %s is not a real path in the pack", lower)
	}
	mountPoint := filepath.Join(w.dataPath(), spec.target)
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
	if !w.executable {
		flags |= unix.MS_NOEXEC
	}
	options := "lowerdir=" + lower + ",upperdir=" + upper + ",workdir=" + work
	if err := unix.Mount("overlay", mountPoint, "overlay", flags, options); err != nil {
		return "", fmt.Errorf("merging %s into %s: %w", lower, mountPoint, err)
	}
	// overlayfs performs every upper-layer operation as the mounter, so upper and work stay ours.
	if err := os.Chown(mountPoint, w.owner, w.owner); err != nil {
		return "", errors.Join(err, unix.Unmount(mountPoint, 0))
	}
	return mountPoint, nil
}

func runFormatter(args []string) error {
	if len(args) != 4 {
		return errors.New("invalid formatter invocation")
	}
	owner, err := strconv.Atoi(args[3])
	if err != nil || owner < 0 || owner > maxOwner {
		return errors.New("invalid formatter owner")
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
	// root_owner hands the volume to the login account. root_perms adds group
	// write and setgid, because the container writing this tree runs as uid 0
	// with the volume gid and no CAP_DAC_OVERRIDE, and new directories have to
	// stay in the group as it grows. mkfs has to set both: it writes the root
	// inode directly, whereas a chmod afterwards would need CAP_FOWNER, which
	// this formatter has just dropped.
	root := fmt.Sprintf("root_owner=%d:%d,root_perms=2775", owner, owner)
	// Nothing is left to first use: dm-integrity holds no tag for a block that was
	// never written, so a lazy table or journal reads back as an I/O error.
	return syscall.Exec(mkfsPath, []string{mkfsPath, "-F", "-q", "-E", root + ",lazy_itable_init=0,lazy_journal_init=0", args[2]}, []string{})
}

func listen(path string, owner int) (*net.UnixListener, error) {
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("refusing to replace non-socket %s", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	listener, err := net.ListenUnix("unixpacket", &net.UnixAddr{Name: path, Net: "unixpacket"})
	if err != nil {
		return nil, err
	}
	listener.SetUnlinkOnClose(true)
	if err := os.Chmod(path, 0o600); err != nil {
		listener.Close()
		return nil, err
	}
	if err := os.Chown(path, owner, owner); err != nil {
		listener.Close()
		return nil, err
	}
	return listener, nil
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
