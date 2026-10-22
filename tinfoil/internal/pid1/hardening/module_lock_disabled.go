//go:build !tinfoil_gpu

package hardening

import (
	"errors"
	"fmt"
	"os"
)

func LockKernelModules() error {
	_, err := os.Stat("/proc/sys/kernel/modules_disabled")
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return fmt.Errorf("CPU runtime requires a kernel without module support")
}
