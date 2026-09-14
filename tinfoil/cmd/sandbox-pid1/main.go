package main

import (
	"context"
	"os"
	"time"

	"tinfoil/internal/pid1/supervisor"
	variant "tinfoil/internal/sandboxvariant"
	"tinfoil/pid1"
)

const (
	sandboxName       = "tinfoil-sandbox"
	sandboxReadyLimit = 30 * time.Second
)

func lifecycleSpec() pid1.Spec {
	return pid1.Spec{
		StartWorkload:    startWorkload,
		RequiredServices: requiredServices(),
		ShutdownGroups:   shutdownGroups(),
		Policies:         variant.Policies(),
	}
}

func main() { pid1.Main(lifecycleSpec()) }

func startWorkload(ctx context.Context, deps pid1.Deps, _ *os.File) error {
	return deps.Services.Start(ctx, supervisor.Service{
		Name: sandboxName, Required: true, Restart: false,
		Command: pid1.HardenedCommand(variant.ServiceSandbox, variant.Binary),
		Ready:   pid1.EndpointReady("tcp", variant.APIAddress, sandboxReadyLimit),
	})
}

func requiredServices() []string { return []string{sandboxName, pid1.ShimName} }

func shutdownGroups() [][]string { return [][]string{{pid1.ShimName}, {sandboxName}} }
