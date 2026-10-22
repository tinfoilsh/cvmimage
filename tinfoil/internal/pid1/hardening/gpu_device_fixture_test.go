package hardening

import "fmt"

func gpuDeviceFixture() []string {
	const deviceSlots = 16
	names := []string{"nvidiactl", "nvidia-uvm", "nvidia-uvm-tools", "nvidia-caps", "nvidia-nvswitchctl", "nvidia-nvlink"}
	for index := 0; index < deviceSlots; index++ {
		names = append(names, fmt.Sprintf("nvidia%d", index), fmt.Sprintf("nvidia-nvswitch%d", index))
	}
	return names
}
