package pid1

import (
	"os"
	"slices"
	"strings"
	"testing"

	"tinfoil/internal/pid1/hardening"
	"tinfoil/internal/pid1/supervisor"
)

func TestDeclaredServiceControlsReadinessAndHardening(t *testing.T) {
	policy := hardening.Policy{NoNewPrivileges: true}
	worker := Service{
		Service: supervisor.Service{Name: "worker", Required: true, Command: supervisor.Command{Path: "/worker", Args: []string{"--serve"}}},
		Policy:  &policy,
	}
	spec := Spec{Services: []Service{worker}}
	var ready bool
	state := newReadiness(spec.requiredServices(), func(value bool) error { ready = value; return nil })
	if err := state.Publish(); err != nil {
		t.Fatal(err)
	}
	if ready {
		t.Fatal("ready before the declared worker started")
	}
	process := worker.Process()
	if process.Command.Path != selfExecPath || !slices.Equal(process.Command.Args, []string{"--exec-service", "worker", "--", "/worker", "--serve"}) {
		t.Fatalf("hardening command = %+v", process.Command)
	}
	state.Update(supervisor.State{Name: process.Name, Required: process.Required, Ready: true})
	if !ready {
		t.Fatal("declared worker did not satisfy readiness")
	}
	state.Update(supervisor.State{Name: process.Name, Required: process.Required, Ready: false})
	if ready {
		t.Fatal("worker failure did not withdraw readiness")
	}
}

func TestServiceCommandsHaveIndependentArgumentsAndFiles(t *testing.T) {
	t.Setenv("TINFOIL_SERVICE_TEST", "before")
	service := Service{Service: supervisor.Service{Name: "worker", Command: supervisor.Command{Path: "/worker", Args: []string{"--serve"}}}}
	t.Setenv("TINFOIL_SERVICE_TEST", "after")
	first := service.Process()
	first.Command.Args[0] = "changed"
	file, err := os.CreateTemp(t.TempDir(), "handoff")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	first.Command = WithSecretHandoff(first.Command, file)
	second := service.Process()
	if !slices.Equal(second.Command.Args, []string{"--serve"}) || len(second.Command.ExtraFiles) != 0 {
		t.Fatalf("shared command state = %+v", second.Command)
	}
	if !slices.Contains(second.Command.Env, "TINFOIL_SERVICE_TEST=after") {
		t.Fatal("service captured the environment before PID 1 configured it")
	}
}

func TestSpecRejectsDuplicateServiceDefinitions(t *testing.T) {
	spec := newLifecycleHarness().deps.spec
	spec.Services = append(spec.Services, spec.Services[0])
	if err := spec.validate(); err == nil || !strings.Contains(err.Error(), "duplicate service") {
		t.Fatalf("validation error = %v", err)
	}
}
