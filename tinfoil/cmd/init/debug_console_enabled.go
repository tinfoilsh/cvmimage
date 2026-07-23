//go:build tinfoil_debug_image && linux && amd64

package main

import (
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"

	"tinfoil/internal/pid1/supervisor"
)

const (
	debugConsoleArg = "--tinfoil-debug-console"
	debugConsoleTTY = "/dev/hvc0"
	debugShellPath  = "/usr/bin/busybox"
)

func dispatchDebugConsole(args []string) (bool, error) {
	if len(args) != 2 || args[1] != debugConsoleArg {
		return false, nil
	}
	return true, execDebugConsole()
}

func startDebugConsole(manager *supervisor.Manager) error {
	initLogf("debug image: starting static shell on %s", debugConsoleTTY)
	_, err := manager.Start(debugConsoleCommand())
	return err
}

func debugConsoleCommand() supervisor.Command {
	return command("tinfoil-debug-console", selfExecPath, debugConsoleArg)
}

func execDebugConsole() error {
	if err := unix.Setpgid(0, os.Getppid()); err != nil {
		return fmt.Errorf("join PID1 process group: %w", err)
	}
	if _, err := unix.Setsid(); err != nil {
		return fmt.Errorf("create console session: %w", err)
	}
	console, err := unix.Open(debugConsoleTTY, unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open %s: %w", debugConsoleTTY, err)
	}
	defer unix.Close(console)
	if err := unix.IoctlSetInt(console, unix.TIOCSCTTY, 0); err != nil {
		return fmt.Errorf("acquire %s: %w", debugConsoleTTY, err)
	}
	if err := unix.IoctlSetPointerInt(console, unix.TIOCSPGRP, os.Getpid()); err != nil {
		return fmt.Errorf("foreground %s: %w", debugConsoleTTY, err)
	}
	for descriptor := 0; descriptor <= 2; descriptor++ {
		if err := unix.Dup3(console, descriptor, 0); err != nil {
			return fmt.Errorf("attach %s to fd %d: %w", debugConsoleTTY, descriptor, err)
		}
	}
	if console > 2 {
		if err := unix.Close(console); err != nil {
			return fmt.Errorf("close console descriptor: %w", err)
		}
		console = -1
	}
	if err := unix.Chdir("/"); err != nil {
		return fmt.Errorf("chdir root: %w", err)
	}
	return syscall.Exec(debugShellPath, []string{"ash", "-i"}, []string{
		"HOME=/root",
		"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
		"TERM=linux",
	})
}
