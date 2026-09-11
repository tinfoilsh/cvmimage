package pid1

import (
	"fmt"
	"slices"

	"tinfoil/internal/bootstate"
	"tinfoil/internal/pid1/hardening"
	"tinfoil/internal/pid1/supervisor"
)

// Service declares a process and, when needed, its self-exec hardening policy.
type Service struct {
	supervisor.Service
	Policy *hardening.Policy
}

// Process prepares a fresh command using the environment established by PID 1.
func (s Service) Process() supervisor.Service {
	process := s.Service
	command := process.Command
	if s.Policy != nil {
		command = HardenedCommand(hardening.Service(s.Name), command.Path, command.Args...)
	} else {
		command.Name = s.Name
		command.Args = slices.Clone(command.Args)
		command.Env = childEnv()
		command.Dir = "/"
	}
	if s.Command.Env != nil {
		command.Env = slices.Clone(s.Command.Env)
	}
	if s.Command.Dir != "" {
		command.Dir = s.Command.Dir
	}
	command.ExtraFiles = slices.Clone(s.Command.ExtraFiles)
	process.Command = command
	return process
}

func BootService() Service {
	policy := hardening.BootPolicy()
	return Service{
		Service: supervisor.Service{
			Name:    string(hardening.ServiceBoot),
			Command: supervisor.Command{Path: bootstate.BootBinary},
		},
		Policy: &policy,
	}
}

func ShimService(policy hardening.Policy) Service {
	return Service{
		Service: supervisor.Service{
			Name: ShimName, Required: true, Restart: true,
			Command: supervisor.Command{Path: bootstate.ShimBinary},
			Ready:   EndpointReady("tcp", "127.0.0.1:443", shimReadyLimit),
			PIDFile: bootstate.ShimPIDPath,
		},
		Policy: &policy,
	}
}

func (s Spec) requiredServices() []string {
	var names []string
	for _, service := range s.Services {
		if service.Required {
			names = append(names, service.Name)
		}
	}
	return names
}

func (s Spec) service(name string) (Service, bool) {
	for _, service := range s.Services {
		if service.Name == name {
			return service, true
		}
	}
	return Service{}, false
}

func (s Spec) ApplyService(name hardening.Service) error {
	service, ok := s.service(string(name))
	if !ok || service.Policy == nil {
		return fmt.Errorf("unknown service hardening policy %q", name)
	}
	return hardening.Apply(name, *service.Policy)
}

func (s Spec) validate() error {
	if s.StartWorkload == nil || len(s.requiredServices()) == 0 || len(s.BootStages) == 0 {
		return fmt.Errorf("incomplete pid1 spec")
	}
	seen := make(map[string]bool)
	for _, service := range s.Services {
		if service.Name == "" || service.Command.Path == "" || seen[service.Name] {
			return fmt.Errorf("invalid or duplicate service %q", service.Name)
		}
		seen[service.Name] = true
	}
	for _, name := range []hardening.Service{hardening.ServiceBoot, hardening.ServiceShim} {
		service, ok := s.service(string(name))
		if !ok || service.Policy == nil {
			return fmt.Errorf("missing %s policy", name)
		}
	}
	return nil
}
