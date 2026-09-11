package variant

import (
	"golang.org/x/sys/unix"
	"tinfoil/internal/boot"
	"tinfoil/internal/pid1/hardening"
)

const (
	ServiceContainers hardening.Service = "tinfoil-containers"
	ServiceEgress     hardening.Service = "tinfoil-egress"
	DockerSocket                        = "/run/docker.sock"
)

func BootStages() []string {
	return []string{
		boot.StageConfig, boot.StageNetwork, boot.StageIdentity, boot.StageCPUAttestation,
		boot.StageGPUAttestation, boot.StageCertificate, boot.StageKeyserverSecrets,
		boot.StageRegistryAuth, boot.StageFirewall, boot.StageModels, boot.StageContainers, boot.StageShim,
	}
}

func Policies() map[hardening.Service]hardening.Policy {
	return map[hardening.Service]hardening.Policy{
		hardening.ServiceBoot: hardening.BootPolicy(),
		hardening.ServiceShim: hardening.ShimPolicy(),
		ServiceContainers:     hardening.RestrictedPolicy([]int{unix.CAP_NET_ADMIN}, []uint32{unix.AF_UNIX, unix.AF_INET, unix.AF_INET6, unix.AF_NETLINK}),
		ServiceEgress:         hardening.RestrictedPolicy([]int{unix.CAP_NET_ADMIN}, []uint32{unix.AF_INET, unix.AF_INET6, unix.AF_NETLINK}),
	}
}
