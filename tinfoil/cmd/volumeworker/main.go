package main

import (
	"context"
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

	maxOwner       = 65534
	keyBytes       = 64
	blankProbeSize = 1 << 20
	requestTimeout = 5 * time.Second

	opStatus     byte = 0
	opUnlock     byte = 1
	opInitialize byte = 2

	responseOK       byte = 0
	responseRejected byte = 1
	responseFailed   byte = 2
	responseLocked   byte = 3
)

var namePattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)

type invocation struct {
	models     int
	index      int
	name       string
	executable bool
	owner      int
}

type mountState struct {
	id     uint64
	device uint64
}

type worker struct {
	name       string
	executable bool
	owner      int
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
	if mapped {
		if info.OpenCount > 0 {
			return false, fmt.Errorf("mapping %s is open without its mount", w.mapperName())
		}
		if err := devicemapper.Remove(w.control, w.mapperName()); err != nil {
			return false, err
		}
	}
	if target.id != parent.id && target.device != parent.device {
		return false, fmt.Errorf("unexpected mount at %s", w.dataPath())
	}
	return false, nil
}

func (w *worker) serve(connection *net.UnixConn) error {
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(requestTimeout)); err != nil {
		return err
	}
	var packet [keyBytes + 2]byte
	defer clear(packet[:])
	n, err := connection.Read(packet[:])
	if err != nil {
		return err
	}
	status, requestErr := w.handle(packet[:n])
	if _, err := connection.Write([]byte{status}); err != nil {
		return errors.Join(requestErr, err)
	}
	return requestErr
}

func (w *worker) handle(packet []byte) (byte, error) {
	if len(packet) == 1 && packet[0] == opStatus {
		return responseLocked, nil
	}
	if len(packet) != keyBytes+1 {
		return responseRejected, errors.New("invalid request size")
	}
	if packet[0] != opUnlock && packet[0] != opInitialize {
		return responseRejected, errors.New("invalid request operation")
	}
	initialize := packet[0] == opInitialize
	if initialize {
		blank, err := blockDeviceBlank(w.source)
		if err != nil {
			return responseFailed, err
		}
		if !blank {
			return responseRejected, errors.New("storage volume is not blank")
		}
	}
	if err := w.activate(packet[1:], initialize); err != nil {
		return responseFailed, err
	}
	w.unlocked = true
	return responseOK, nil
}

func (w *worker) activate(key []byte, initialize bool) (result error) {
	mappedDevice, err := devicemapper.ActivateWritableCrypt(w.control, w.source, w.mapperName(), key)
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
	return nil
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
	// the volume worker is not given.
	root := fmt.Sprintf("root_owner=%d:%d,root_perms=2775", owner, owner)
	return syscall.Exec(mkfsPath, []string{mkfsPath, "-F", "-q", "-E", root, args[2]}, []string{})
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
