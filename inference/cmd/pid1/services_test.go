package main

import (
	"context"
	"os"
	"reflect"
	"slices"
	"testing"

	"golang.org/x/sys/unix"

	"tinfoil/inference/internal/variant"
	"tinfoil/internal/pid1/hardening"
	"tinfoil/internal/pid1/supervisor"
	"tinfoil/pid1"
)

func TestInferencePoliciesPreserveRestrictions(t *testing.T) {
	policies := map[hardening.Service]hardening.Policy{}
	for _, service := range lifecycleSpec().Services {
		if service.Policy != nil {
			policies[hardening.Service(service.Name)] = *service.Policy
		}
	}
	if len(policies) != 5 {
		t.Fatalf("policies = %#v", policies)
	}
	for _, service := range []hardening.Service{variant.ServiceContainers, variant.ServiceEgress} {
		policy := policies[service]
		if !policy.NoNewPrivileges || !policy.RestrictFilesystems || !policy.RestrictNamespaceOps || len(policy.AttestationDevices) != 0 {
			t.Fatalf("restrictions for %s = %#v", service, policy)
		}
		if !reflect.DeepEqual(policy.BoundCapabilities, []int{unix.CAP_NET_ADMIN}) {
			t.Fatalf("capabilities for %s = %v", service, policy.BoundCapabilities)
		}
		wantDomains := []uint32{unix.AF_INET, unix.AF_INET6, unix.AF_NETLINK}
		if service == variant.ServiceContainers {
			wantDomains = append([]uint32{unix.AF_UNIX}, wantDomains...)
		}
		if !reflect.DeepEqual(policy.AllowedSocketDomains, wantDomains) {
			t.Fatalf("socket domains for %s = %v", service, policy.AllowedSocketDomains)
		}
	}
}

type recordedServices struct{ started []supervisor.Service }

func (s *recordedServices) Start(_ context.Context, service supervisor.Service) error {
	s.started = append(s.started, service)
	return nil
}

func TestInferenceStartupUsesDeclaredServicesAndFreshHandoff(t *testing.T) {
	spec := lifecycleSpec()
	services := &recordedServices{}
	runtime := pid1.Runtime{Services: services}
	runtime.Cmdline.Debug = true
	handoff, err := os.CreateTemp(t.TempDir(), "handoff")
	if err != nil {
		t.Fatal(err)
	}
	defer handoff.Close()
	if err := spec.StartDaemons(t.Context(), runtime); err != nil {
		t.Fatal(err)
	}
	if err := spec.StartWorkload(t.Context(), runtime, handoff); err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, process := range services.started {
		names = append(names, process.Name)
		declared := false
		for _, service := range spec.Services {
			if service.Name == process.Name {
				declared = true
				if process.Required != service.Required {
					t.Fatalf("readiness diverged for %s", process.Name)
				}
			}
		}
		if !declared {
			t.Fatalf("started undeclared service %s", process.Name)
		}
	}
	if !slices.Equal(names, []string{containerdName, dockerName, containersName, egressName}) {
		t.Fatalf("startup = %v", names)
	}
	first := services.started[2].Command
	if !slices.Contains(first.Args, "--debug=true") || !slices.Contains(first.Args, "--secrets-fd=3") || len(first.ExtraFiles) != 1 || first.ExtraFiles[0] != handoff {
		t.Fatalf("container command = %+v", first)
	}
	runtime.Cmdline.Debug = false
	if err := spec.StartWorkload(t.Context(), runtime, handoff); err != nil {
		t.Fatal(err)
	}
	second := services.started[4].Command
	if slices.Contains(second.Args, "--debug=true") || !slices.Contains(second.Args, "--debug=false") || len(second.ExtraFiles) != 1 {
		t.Fatalf("container command retained an earlier invocation: %+v", second)
	}
}
