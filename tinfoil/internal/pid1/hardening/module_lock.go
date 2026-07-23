package hardening

import (
	"fmt"
	"strings"

	"golang.org/x/sys/unix"
)

const modulesDisabledPath = "/proc/sys/kernel/modules_disabled"

// LockKernelModules irreversibly closes the kernel module-loading interface
// before general services start. The kernel enforces the transition globally
// and checks it before CAP_SYS_MODULE, so no later process can load or
// unload a module regardless of its capabilities.
func LockKernelModules() error {
	return lockKernelModules(linuxModuleLockKernel{})
}

type moduleLockKernel interface {
	writeModulesDisabled([]byte) (int, error)
	readModulesDisabled() ([]byte, error)
}

func lockKernelModules(kernel moduleLockKernel) error {
	value := []byte("1\n")
	written, err := kernel.writeModulesDisabled(value)
	if err != nil {
		return fmt.Errorf("write %s: %w", modulesDisabledPath, err)
	}
	if written != len(value) {
		return fmt.Errorf("write %s: wrote %d of %d bytes", modulesDisabledPath, written, len(value))
	}
	state, err := kernel.readModulesDisabled()
	if err != nil {
		return fmt.Errorf("read back %s: %w", modulesDisabledPath, err)
	}
	if strings.TrimSpace(string(state)) != "1" {
		return fmt.Errorf("verify %s: got %q, want 1", modulesDisabledPath, strings.TrimSpace(string(state)))
	}
	return nil
}

type linuxModuleLockKernel struct{}

func (linuxModuleLockKernel) writeModulesDisabled(value []byte) (int, error) {
	descriptor, err := unix.Open(modulesDisabledPath, unix.O_WRONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return 0, err
	}
	written, writeErr := unix.Write(descriptor, value)
	closeErr := unix.Close(descriptor)
	if writeErr != nil {
		return written, writeErr
	}
	return written, closeErr
}

func (linuxModuleLockKernel) readModulesDisabled() ([]byte, error) {
	descriptor, err := unix.Open(modulesDisabledPath, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	buffer := make([]byte, 16)
	read, readErr := unix.Read(descriptor, buffer)
	closeErr := unix.Close(descriptor)
	if readErr != nil {
		return nil, readErr
	}
	return buffer[:read], closeErr
}
