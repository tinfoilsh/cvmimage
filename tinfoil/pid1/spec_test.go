package pid1

import (
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"

	"tinfoil/internal/pid1/hardening"
	"tinfoil/internal/pid1/supervisor"
)

func TestSpecRejectsUnknownPolicyBeforeExec(t *testing.T) {
	spec := Spec{}
	err := execService([]string{"missing", "--", "/unused"}, spec.ApplyService,
		func(string, []string, []string) error {
			t.Fatal("executed an unknown policy")
			return nil
		})
	if err == nil || !strings.Contains(err.Error(), "unknown service hardening policy") {
		t.Fatalf("error = %v", err)
	}
}

func TestSpecReexecAppliesPolicyAndEnvironment(t *testing.T) {
	switch os.Getenv("TINFOIL_SPEC_TEST_PHASE") {
	case "target":
		if os.Getenv("TINFOIL_SPEC_TEST_VALUE") != "declared" || os.Getenv("PATH") != "/usr/sbin:/usr/bin:/sbin:/bin" || os.Getenv(pid1Env) != pid1EnvValue {
			os.Exit(20)
		}
		_, _, errno := unix.RawSyscall(unix.SYS_GETPPID, 0, 0, 0)
		if errno != syscall.EPERM {
			os.Exit(21)
		}
		os.Exit(0)
	case "wrapper":
		spec := newLifecycleHarness().deps.spec
		spec.Environment = map[string]string{
			"TINFOIL_SPEC_TEST_PHASE": "target",
			"TINFOIL_SPEC_TEST_VALUE": "declared",
		}
		policy := hardening.Policy{NoNewPrivileges: true, DeniedSyscalls: []uint32{unix.SYS_GETPPID}}
		spec.Services = append(spec.Services, Service{Service: supervisor.Service{Name: "worker", Command: Command("worker", "/worker")}, Policy: &policy})
		binary := os.Args[0]
		if err := ExecService([]string{"worker", "--", binary, "-test.run=^TestSpecReexecAppliesPolicyAndEnvironment$"}, spec); err != nil {
			t.Fatal(err)
		}
		os.Exit(22)
	}
	command := exec.Command(os.Args[0], "-test.run=^TestSpecReexecAppliesPolicyAndEnvironment$")
	command.Env = append(os.Environ(), "TINFOIL_SPEC_TEST_PHASE=wrapper", "TINFOIL_SPEC_TEST_VALUE=inherited")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("reexec child: %v: %s", err, output)
	}
}

func TestCommandDoesNotSupplyDockerEnvironment(t *testing.T) {
	t.Setenv("DOCKER_HOST", "")
	if err := os.Unsetenv("DOCKER_HOST"); err != nil {
		t.Fatal(err)
	}
	for _, value := range Command("worker", "/worker").Env {
		if strings.HasPrefix(value, "DOCKER_HOST=") {
			t.Fatal("shared command supplied Docker configuration")
		}
	}
}
