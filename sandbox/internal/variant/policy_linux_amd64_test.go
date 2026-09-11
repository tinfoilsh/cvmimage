package variant

import (
	"os"
	"os/exec"
	"reflect"
	"runtime"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
	"tinfoil/internal/bootstate"
	"tinfoil/internal/pid1/hardening"
)

func TestSandboxPolicyPreservesRestrictions(t *testing.T) {
	want := hardening.Policy{NoNewPrivileges: true, DeniedSyscalls: []uint32{
		unix.SYS_ACCT, unix.SYS_DELETE_MODULE, unix.SYS_FINIT_MODULE, unix.SYS_INIT_MODULE,
		unix.SYS_IOPERM, unix.SYS_IOPL, unix.SYS_KEXEC_FILE_LOAD, unix.SYS_KEXEC_LOAD,
		unix.SYS_REBOOT, unix.SYS_SWAPOFF, unix.SYS_SWAPON,
	}}
	policies := Policies()
	if len(policies) != 3 || !reflect.DeepEqual(policies[ServiceSandbox], want) {
		t.Fatalf("sandbox policies = %#v", policies)
	}
}

func TestSandboxPolicyDeniesModuleLoading(t *testing.T) {
	if os.Getenv("TINFOIL_SANDBOX_POLICY_TEST") == "1" {
		runtime.LockOSThread()
		if err := hardening.Apply(ServiceSandbox, Policies()[ServiceSandbox]); err != nil {
			os.Exit(20)
		}
		_, _, errno := unix.RawSyscall(unix.SYS_FINIT_MODULE, ^uintptr(0), 0, 0)
		if errno != syscall.EPERM {
			os.Exit(21)
		}
		os.Exit(0)
	}
	command := exec.Command(os.Args[0], "-test.run=^TestSandboxPolicyDeniesModuleLoading$")
	command.Env = append(os.Environ(), "TINFOIL_SANDBOX_POLICY_TEST=1")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("policy child: %v: %s", err, output)
	}
}

func TestBootCompletionWaitsForSandbox(t *testing.T) {
	state := bootstate.State{}
	for _, name := range BootStages() {
		if name == "gpu-attestation" || name == "firewall" || name == "containers" || name == bootstate.StageRegistryAuth {
			t.Fatalf("unrelated stage %s", name)
		}
		status := bootstate.StatusOK
		if name == Stage {
			status = bootstate.StatusPending
		}
		state.Stages = append(state.Stages, bootstate.Stage{Name: name, Status: status})
	}
	if state.IsComplete() {
		t.Fatal("completed before sandbox readiness")
	}
	for i := range state.Stages {
		if state.Stages[i].Name == Stage {
			state.Stages[i].Status = bootstate.StatusFailed
			state.Stages[i].Detail = "SSH preparation failed"
		}
	}
	if !state.IsComplete() || !state.HasFailed() {
		t.Fatal("failed sandbox did not resolve boot")
	}
	if _, ok := state.FailureSummary(BootStages()); !ok {
		t.Fatal("sandbox failure rejected by diagnostic validation")
	}
}
