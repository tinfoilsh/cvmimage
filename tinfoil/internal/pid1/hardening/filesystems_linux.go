package hardening

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

const (
	attestationDeviceSource = "/run/tinfoil-attestation-devices"
	attestationSysSource    = "/run/tinfoil-attestation-sys"
	tdxReportSource         = "/sys/kernel/config/tsm"
)

func (linuxServiceKernel) restrictFilesystems(exposeAttestation bool) error {
	return restrictServiceFilesystems(linuxFilesystemKernel{}, exposeAttestation)
}

type filesystemKernel interface {
	unshare(int) error
	mount(string, string, string, uintptr, string) error
	unmount(string, int) error
	pathKind(string) (devicePathKind, error)
	makeTarget(string, devicePathKind) error
	remove(string) error
}

type linuxFilesystemKernel struct{}

func (linuxFilesystemKernel) unshare(flags int) error {
	return unix.Unshare(flags)
}

func (linuxFilesystemKernel) mount(source, target, filesystemType string, flags uintptr, data string) error {
	return unix.Mount(source, target, filesystemType, flags, data)
}

func (linuxFilesystemKernel) unmount(target string, flags int) error {
	return unix.Unmount(target, flags)
}

type devicePathKind uint8

const (
	devicePathMissing devicePathKind = iota
	devicePathNode
	devicePathDirectory
)

func (linuxFilesystemKernel) pathKind(path string) (devicePathKind, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return devicePathMissing, nil
	}
	if err != nil {
		return devicePathMissing, err
	}
	if info.IsDir() {
		return devicePathDirectory, nil
	}
	if info.Mode()&os.ModeCharDevice != 0 {
		return devicePathNode, nil
	}
	return devicePathMissing, fmt.Errorf("unexpected attestation device path type %s", info.Mode())
}

func (linuxFilesystemKernel) makeTarget(path string, kind devicePathKind) error {
	switch kind {
	case devicePathDirectory:
		return os.MkdirAll(path, 0555)
	case devicePathNode:
		file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL, 0000)
		if err != nil {
			return err
		}
		return file.Close()
	default:
		return fmt.Errorf("invalid attestation device path kind %d", kind)
	}
}

func (linuxFilesystemKernel) remove(path string) error {
	return os.RemoveAll(path)
}

func restrictServiceFilesystems(kernel filesystemKernel, exposeAttestation bool) error {
	if err := kernel.unshare(unix.CLONE_NEWNS); err != nil {
		return fmt.Errorf("unshare mount namespace: %w", err)
	}
	if err := kernel.mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return fmt.Errorf("make mounts private: %w", err)
	}
	if err := mountRestrictedProc(kernel); err != nil {
		return err
	}
	if exposeAttestation {
		if err := mountAttestationDeviceView(kernel); err != nil {
			return err
		}
	} else if err := mountEmptyReadOnly(kernel, "/dev"); err != nil {
		return err
	}
	if exposeAttestation {
		if err := mountAttestationSysView(kernel); err != nil {
			return err
		}
	} else if err := mountEmptyReadOnly(kernel, "/sys"); err != nil {
		return err
	}
	return nil
}

func mountAttestationSysView(kernel filesystemKernel) (result error) {
	kind, err := kernel.pathKind(tdxReportSource)
	if err != nil {
		return fmt.Errorf("inspect TDX report interface: %w", err)
	}
	if kind == devicePathMissing {
		return mountEmptyReadOnly(kernel, "/sys")
	}
	if kind != devicePathDirectory {
		return fmt.Errorf("TDX report interface is not a directory")
	}
	if err := resetStagingDirectory(kernel, attestationSysSource); err != nil {
		return fmt.Errorf("reset attestation sys source: %w", err)
	}
	defer func() {
		result = errors.Join(result, kernel.remove(attestationSysSource))
	}()
	if err := kernel.mount(tdxReportSource, attestationSysSource, "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
		return fmt.Errorf("preserve TDX report interface: %w", err)
	}
	defer func() {
		if err := kernel.unmount(attestationSysSource, unix.MNT_DETACH); err != nil {
			result = errors.Join(result, fmt.Errorf("unmount attestation sys source: %w", err))
		}
	}()

	flags := uintptr(unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC)
	if err := kernel.mount("tmpfs", "/sys", "tmpfs", flags, "size=16k,nr_inodes=16,mode=0755"); err != nil {
		return fmt.Errorf("mount restricted attestation /sys: %w", err)
	}
	if err := kernel.makeTarget(tdxReportSource, devicePathDirectory); err != nil {
		return fmt.Errorf("create TDX report target: %w", err)
	}
	if err := kernel.mount(attestationSysSource, tdxReportSource, "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
		return fmt.Errorf("bind TDX report interface: %w", err)
	}
	if err := kernel.mount("", "/sys", "", flags|unix.MS_REMOUNT|unix.MS_RDONLY, ""); err != nil {
		return fmt.Errorf("remount restricted attestation /sys read-only: %w", err)
	}
	return nil
}

func mountAttestationDeviceView(kernel filesystemKernel) (result error) {
	if err := resetStagingDirectory(kernel, attestationDeviceSource); err != nil {
		return fmt.Errorf("reset attestation device source: %w", err)
	}
	defer func() {
		result = errors.Join(result, kernel.remove(attestationDeviceSource))
	}()
	if err := kernel.mount("/dev", attestationDeviceSource, "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
		return fmt.Errorf("preserve attestation device source: %w", err)
	}
	defer func() {
		if err := kernel.unmount(attestationDeviceSource, unix.MNT_DETACH); err != nil {
			result = errors.Join(result, fmt.Errorf("unmount attestation device source: %w", err))
		}
	}()

	flags := uintptr(unix.MS_NOSUID | unix.MS_NOEXEC)
	if err := kernel.mount("tmpfs", "/dev", "tmpfs", flags, "size=64k,nr_inodes=128,mode=0755"); err != nil {
		return fmt.Errorf("mount restricted attestation /dev: %w", err)
	}
	for _, relative := range attestationDevicePaths() {
		source := filepath.Join(attestationDeviceSource, relative)
		kind, err := kernel.pathKind(source)
		if err != nil {
			return fmt.Errorf("inspect attestation device %s: %w", relative, err)
		}
		if kind == devicePathMissing {
			continue
		}
		target := filepath.Join("/dev", relative)
		if err := kernel.makeTarget(target, kind); err != nil {
			return fmt.Errorf("create attestation device target %s: %w", relative, err)
		}
		bindFlags := uintptr(unix.MS_BIND)
		if kind == devicePathDirectory {
			bindFlags |= unix.MS_REC
		}
		if err := kernel.mount(source, target, "", bindFlags, ""); err != nil {
			return fmt.Errorf("bind attestation device %s: %w", relative, err)
		}
	}
	if err := kernel.mount("", "/dev", "", flags|unix.MS_REMOUNT|unix.MS_RDONLY, ""); err != nil {
		return fmt.Errorf("remount restricted attestation /dev read-only: %w", err)
	}
	return nil
}

func resetStagingDirectory(kernel filesystemKernel, path string) error {
	if err := kernel.remove(path); err != nil {
		return fmt.Errorf("remove stale path: %w", err)
	}
	if err := kernel.makeTarget(path, devicePathDirectory); err != nil {
		return fmt.Errorf("create clean directory: %w", err)
	}
	return nil
}

func attestationDevicePaths() []string {
	paths := []string{
		"null",
		"tdx_guest",
		"sev-guest",
		"nvidiactl",
		"nvidia-uvm",
		"nvidia-uvm-tools",
		"nvidia-caps",
		"nvidia-nvswitchctl",
		"nvidia-nvlink",
	}
	for index := 0; index < 16; index++ {
		paths = append(paths, fmt.Sprintf("nvidia%d", index), fmt.Sprintf("nvidia-nvswitch%d", index))
	}
	return paths
}

func mountRestrictedProc(kernel filesystemKernel) error {
	flags := uintptr(unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC)
	if err := kernel.mount("proc", "/proc", "proc", flags, "hidepid=2"); err != nil {
		return fmt.Errorf("mount restricted /proc: %w", err)
	}
	if err := kernel.mount("", "/proc", "", flags|unix.MS_REMOUNT|unix.MS_RDONLY, ""); err != nil {
		return fmt.Errorf("remount restricted /proc read-only: %w", err)
	}
	return nil
}

func mountEmptyReadOnly(kernel filesystemKernel, target string) error {
	flags := uintptr(unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC)
	if err := kernel.mount("tmpfs", target, "tmpfs", flags, "size=4k,nr_inodes=1,mode=0555"); err != nil {
		return fmt.Errorf("mount empty %s: %w", target, err)
	}
	if err := kernel.mount("", target, "", flags|unix.MS_REMOUNT|unix.MS_RDONLY, ""); err != nil {
		return fmt.Errorf("remount %s read-only: %w", target, err)
	}
	return nil
}
