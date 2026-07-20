package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

const debugFailureShellFlag = "tinfoil-debug=on"

var (
	debugFailureConsolePath = "/dev/console"
	debugFailureShellPath   = "/bin/sh"
	runDebugFailureShell    = runConsoleDebugFailureShell
)

func maybeDropToDebugFailureShell(bootErr error) {
	if !debugFailureShellEnabled() {
		return
	}
	bootLogf("debug failure shell enabled after boot error: %v", bootErr)
	bootLogf("starting /bin/sh on /dev/console; exit the shell to finish fatal boot")
	if err := runDebugFailureShell(); err != nil {
		bootLogf("debug failure shell unavailable: %v", err)
	}
}

func debugFailureShellEnabled() bool {
	data, err := os.ReadFile(procCmdlinePath)
	if err != nil {
		return false
	}
	for _, field := range strings.Fields(string(data)) {
		if field == debugFailureShellFlag {
			return true
		}
	}
	return false
}

func runConsoleDebugFailureShell() error {
	console, err := os.OpenFile(debugFailureConsolePath, os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("open %s: %w", debugFailureConsolePath, err)
	}
	defer console.Close()

	cmd := exec.Command(debugFailureShellPath, "-i")
	cmd.Dir = "/"
	cmd.Env = append(os.Environ(),
		"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
		"TERM=xterm-256color",
		"TINFOIL_BOOT_FAILURE_SHELL=1",
	)
	cmd.Stdin = console
	cmd.Stdout = console
	cmd.Stderr = console
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid:    true,
		Setctty:   true,
		Ctty:      0,
		Pdeathsig: syscall.SIGKILL,
	}
	if err := cmd.Run(); err != nil {
		return err
	}
	return nil
}
