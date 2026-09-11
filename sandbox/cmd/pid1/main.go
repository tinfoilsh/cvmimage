package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"tinfoil/pid1"
)

func main() {
	log.SetFlags(0)
	spec := lifecycleSpec()
	if len(os.Args) > 1 && os.Args[1] == "--exec-service" {
		if err := pid1.ExecService(os.Args[2:], spec); err != nil {
			fmt.Fprintf(os.Stderr, "tinfoil-pid1: exec-service: %v\n", err)
			os.Exit(127)
		}
		panic("syscall.Exec returned without an error")
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := pid1.Run(ctx, spec); err != nil {
		pid1.Logf("fatal after cleanup: %v; parking", err)
	} else {
		pid1.Logf("shutdown complete; powering off")
		if err := unix.Reboot(unix.LINUX_REBOOT_CMD_POWER_OFF); err != nil {
			pid1.Logf("power off failed: %v; parking", err)
		}
	}
	// PID 1 must remain alive even when startup or power-off fails.
	for {
		time.Sleep(time.Hour)
	}
}
