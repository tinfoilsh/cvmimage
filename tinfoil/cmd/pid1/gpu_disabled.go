//go:build !tinfoil_gpu

package main

import (
	"context"
	"tinfoil/internal/pid1/supervisor"
)

func initializeGPU(context.Context, *supervisor.Manager, *supervisor.Supervisor) error { return nil }
func gpuServiceNames() []string                                                        { return nil }
