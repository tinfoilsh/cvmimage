package variant

import (
	"golang.org/x/sys/unix"

	"tinfoil/internal/bootstate"
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
		bootstate.StageConfig, bootstate.StageNetwork, bootstate.StageIdentity, bootstate.StageCPUAttestation,
		bootstate.StageCertificate, bootstate.StageKeyserverSecrets, bootstate.StageModels, Stage, bootstate.StageShim,
	}
}

// SandboxPolicy is inherited by SSH sessions, including the owner's debugging tools.
func SandboxPolicy() hardening.Policy {
	return hardening.Policy{NoNewPrivileges: true, DeniedSyscalls: []uint32{
		unix.SYS_ACCT, unix.SYS_DELETE_MODULE, unix.SYS_FINIT_MODULE, unix.SYS_INIT_MODULE,
		unix.SYS_IOPERM, unix.SYS_IOPL, unix.SYS_KEXEC_FILE_LOAD, unix.SYS_KEXEC_LOAD,
		unix.SYS_REBOOT, unix.SYS_SWAPOFF, unix.SYS_SWAPON,
	}}
}
