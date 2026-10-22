//go:build !tinfoil_gpu

package containers

import (
	"fmt"
	"github.com/moby/moby/api/types/container"
)

func configureGPUs(gpus any, _ *container.HostConfig) error {
	if gpus != nil {
		return fmt.Errorf("CPU runtime does not support GPU requests")
	}
	return nil
}
