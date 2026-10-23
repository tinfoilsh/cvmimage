//go:build tinfoil_gpu

package hardening

import "fmt"

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
