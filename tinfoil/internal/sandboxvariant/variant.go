package sandboxvariant

import (
	"fmt"
	"golang.org/x/sys/unix"
	"tinfoil/internal/boot"
	"tinfoil/internal/pid1/hardening"
	"tinfoil/internal/runtimeconfig"
	"tinfoil/internal/volume"
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

func Validate(config *runtimeconfig.Config) error {
	if config.GPUs != 0 || len(config.Containers) != 0 {
		return fmt.Errorf("sandbox does not support GPUs or containers")
	}
	if len(config.Volumes) != 1 {
		return fmt.Errorf("sandbox requires exactly one workspace volume")
	}
	if err := volume.ValidateWorkspace(volume.Spec{VolumeSpec: config.Volumes[0], Models: len(config.Models)}); err != nil {
		return err
	}
	modelName := config.Volumes[0].Overlays[0].Model
	found := false
	for _, model := range config.Models {
		if model.Name == modelName && model.Exec {
			found = true
		}
	}
	if !found {
		return fmt.Errorf("workspace toolchain %q must be an executable model", modelName)
	}
	if config.ShimCfg == nil || config.ShimCfg.UpstreamPort != 8080 || config.ShimCfg.UpstreamContainer != "" {
		return fmt.Errorf("sandbox shim must route to port 8080 on loopback")
	}
	return nil
}
