//go:build tinfoil_debug_image && linux && amd64

package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"tinfoil/internal/pid1/supervisor"
)

const (
	debugConsoleTTY = "/dev/hvc0"
	debugShellPath  = "/usr/bin/busybox"
)

type debugConsole struct {
	process *supervisor.Process
}

func startDebugConsole(_ context.Context, manager *supervisor.Manager) (*debugConsole, error) {
	console, err := os.OpenFile(debugConsoleTTY, os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", debugConsoleTTY, err)
	}
	defer console.Close()

	initLogf("debug image: starting static shell on %s", debugConsoleTTY)
	process, err := manager.StartConsole(debugConsoleCommand(), console)
	if err != nil {
		return nil, err
	}
	return &debugConsole{process: process}, nil
}

func (console *debugConsole) stop(termGrace, killGrace time.Duration) error {
	return console.process.StopConsole(termGrace, killGrace)
}

func parkDebugFailure(ctx context.Context, err error) {
	initLogf("debug image: lifecycle failed: %v; console remains available until shutdown", err)
	<-ctx.Done()
}

func debugConsoleCommand() supervisor.Command {
	return supervisor.Command{
		Name: "tinfoil-debug-console",
		Path: debugShellPath,
		Args: []string{"ash", "-i"},
		Env: []string{
			"HOME=/root",
			"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
			"TERM=linux",
		},
		Dir: "/",
	}
}
