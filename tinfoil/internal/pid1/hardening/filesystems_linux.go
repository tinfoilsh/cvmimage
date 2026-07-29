package hardening

import (
	"fmt"

	"golang.org/x/sys/unix"
)

func (linuxServiceKernel) restrictFilesystems() error {
	return restrictServiceFilesystems(linuxFilesystemKernel{})
}

type filesystemKernel interface {
	unshare(int) error
	mount(string, string, string, uintptr, string) error
}

type linuxFilesystemKernel struct{}

func (linuxFilesystemKernel) unshare(flags int) error {
	return unix.Unshare(flags)
}

func (linuxFilesystemKernel) mount(source, target, filesystemType string, flags uintptr, data string) error {
	return unix.Mount(source, target, filesystemType, flags, data)
}

func restrictServiceFilesystems(kernel filesystemKernel) error {
	if err := kernel.unshare(unix.CLONE_NEWNS); err != nil {
		return fmt.Errorf("unshare mount namespace: %w", err)
	}
	if err := kernel.mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return fmt.Errorf("make mounts private: %w", err)
	}
	if err := mountRestrictedProc(kernel); err != nil {
		return err
	}
	for _, target := range []string{"/dev", "/sys"} {
		if err := mountEmptyReadOnly(kernel, target); err != nil {
			return err
		}
	}
	return nil
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
