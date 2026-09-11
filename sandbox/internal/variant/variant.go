package variant

import (
	"golang.org/x/sys/unix"
	"tinfoil/internal/boot"
	"tinfoil/internal/pid1/hardening"
)

const (
	ServiceSandbox hardening.Service = "tinfoil-sandbox"
	Binary                           = "/usr/bin/tinfoil-sandbox"
	APIAddress                       = "127.0.0.1:8080"
	Stage                            = "sandbox"
)

func BootStages() []string {
	return []string{
		boot.StageConfig, boot.StageNetwork, boot.StageIdentity, boot.StageCPUAttestation,
		boot.StageCertificate, boot.StageKeyserverSecrets, boot.StageModels, Stage, boot.StageShim,
	}
}

func Policies() map[hardening.Service]hardening.Policy {
	return map[hardening.Service]hardening.Policy{
		hardening.ServiceBoot: hardening.BootPolicy(),
		hardening.ServiceShim: hardening.ShimPolicy(),
		// SSH sessions inherit this filter. Workspace owners retain their existing
		// debugging capabilities; kernel replacement remains forbidden.
		ServiceSandbox: {NoNewPrivileges: true, DeniedSyscalls: []uint32{
			unix.SYS_ACCT, unix.SYS_DELETE_MODULE, unix.SYS_FINIT_MODULE, unix.SYS_INIT_MODULE,
			unix.SYS_IOPERM, unix.SYS_IOPL, unix.SYS_KEXEC_FILE_LOAD, unix.SYS_KEXEC_LOAD,
			unix.SYS_REBOOT, unix.SYS_SWAPOFF, unix.SYS_SWAPON,
		}},
	}
}
