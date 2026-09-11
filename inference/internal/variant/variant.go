package variant

import (
	"fmt"

	"tinfoil/internal/bootstate"
	"tinfoil/internal/pid1/hardening"
)

const (
	ServiceContainers hardening.Service = "tinfoil-containers"
	ServiceEgress     hardening.Service = "tinfoil-egress"
	DockerSocket                        = "/run/docker.sock"
)

func BootStages() []string {
	return []string{
		bootstate.StageConfig, bootstate.StageNetwork, bootstate.StageIdentity, bootstate.StageCPUAttestation,
		StageGPUAttestation, bootstate.StageCertificate, bootstate.StageKeyserverSecrets,
		StageRegistryAuth, StageFirewall, bootstate.StageModels, StageContainers, bootstate.StageShim,
	}
}

func ShimPolicy() hardening.Policy {
	policy := hardening.ShimPolicy()
	policy.AttestationDevices = append(policy.AttestationDevices,
		"nvidiactl", "nvidia-uvm", "nvidia-uvm-tools", "nvidia-caps",
		"nvidia-nvswitchctl", "nvidia-nvlink",
	)
	for index := 0; index < 16; index++ {
		policy.AttestationDevices = append(policy.AttestationDevices,
			fmt.Sprintf("nvidia%d", index), fmt.Sprintf("nvidia-nvswitch%d", index))
	}
	return policy
}
