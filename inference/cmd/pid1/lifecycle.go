package main

import (
	"context"
	"fmt"
	"os"

	"tinfoil/inference/internal/nvidia"
	"tinfoil/inference/internal/variant"
	"tinfoil/pid1"
)

func lifecycleSpec() pid1.Spec {
	containerd, docker, containers, egress := inferenceServices()
	control := newSystemNVIDIA()
	persistenced, fabric := nvidiaServices(control)
	return pid1.Spec{
		Services: []pid1.Service{
			pid1.BootService(), pid1.ShimService(variant.ShimPolicy()),
			containerd, docker, containers, egress, persistenced, fabric,
		},
		ShutdownGroups: shutdownGroups(),
		BootStages:     variant.BootStages(),
		Environment:    map[string]string{"DOCKER_HOST": "unix://" + variant.DockerSocket},
		BootstrapDevices: func(ctx context.Context, runtime pid1.Runtime) error {
			return runNVIDIABootstrap(ctx, control, runtime.OneShot, runtime.Services.Start,
				func(status nvidia.BootstrapStatus) error {
					return nvidia.WriteBootstrapStatus(variant.NVIDIABootstrapStatusPath, status)
				})
		},
		StartDaemons: func(ctx context.Context, runtime pid1.Runtime) error {
			if err := runtime.Services.Start(ctx, containerd.Process()); err != nil {
				return err
			}
			return runtime.Services.Start(ctx, docker.Process())
		},
		StartWorkload: func(ctx context.Context, runtime pid1.Runtime, secrets *os.File) error {
			process := containers.Process()
			process.Command.Args = append(process.Command.Args, fmt.Sprintf("--debug=%t", runtime.Cmdline.Debug))
			process.Command = pid1.WithSecretHandoff(process.Command, secrets)
			if err := runtime.Services.Start(ctx, process); err != nil {
				return err
			}
			return runtime.Services.Start(ctx, egress.Process())
		},
	}
}

func shutdownGroups() [][]string {
	return [][]string{
		{egressName, pid1.ShimName},
		{containersName},
		{fabricManagerName, persistencedName},
		{dockerName},
		{containerdName},
	}
}
