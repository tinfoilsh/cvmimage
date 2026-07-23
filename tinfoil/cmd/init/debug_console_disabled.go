//go:build !tinfoil_debug_image

package main

import (
	"context"
	"time"

	"tinfoil/internal/pid1/supervisor"
)

type debugConsole struct{}

func startDebugConsole(context.Context, *supervisor.Manager) (*debugConsole, error) {
	return &debugConsole{}, nil
}

func (*debugConsole) stop(time.Duration, time.Duration) error { return nil }

func parkDebugFailure(error) {}
