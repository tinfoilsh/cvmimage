package main

import (
	"context"
	"os"
	"time"

	"tinfoil/internal/pid1/hardening"
	"tinfoil/internal/pid1/supervisor"
	"tinfoil/pid1"
	"tinfoil/sandbox/internal/variant"
)

const (
	sandboxName       = string(variant.ServiceSandbox)
	sandboxReadyLimit = 30 * time.Second
)

func lifecycleSpec() pid1.Spec {
	policy := variant.SandboxPolicy()
	worker := pid1.Service{
		Service: supervisor.Service{
			Name: sandboxName, Required: true, Restart: true,
			Command: supervisor.Command{Path: variant.Binary},
			Ready:   pid1.EndpointReady("tcp", variant.APIAddress, sandboxReadyLimit),
		},
		Policy: &policy,
	}
	return pid1.Spec{
		Services: []pid1.Service{pid1.BootService(), pid1.ShimService(hardening.ShimPolicy()), worker},
		StartWorkload: func(ctx context.Context, runtime pid1.Runtime, _ *os.File) error {
			return runtime.Services.Start(ctx, worker.Process())
		},
		ShutdownGroups: [][]string{{pid1.ShimName}, {sandboxName}},
		BootStages:     variant.BootStages(),
	}
}
