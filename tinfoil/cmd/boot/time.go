package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"time"

	"tinfoil/internal/boot"
)

const (
	clockBootstrapLimit  = 5 * time.Minute
	clockWaitInterval    = 5 * time.Second
	clockMaxCorrection   = 100 * time.Millisecond
	clockWaitNoSkewLimit = "0"
)

func waitForClock(ctx context.Context, client string) error {
	ctx, cancel := context.WithTimeout(ctx, clockBootstrapLimit)
	defer cancel()
	command := exec.CommandContext(ctx, client, "-u", "root", "-n", "-h", boot.ChronySocketPath,
		"waitsync", strconv.Itoa(int(clockBootstrapLimit/clockWaitInterval)),
		strconv.FormatFloat(clockMaxCorrection.Seconds(), 'f', -1, 64), clockWaitNoSkewLimit,
		strconv.Itoa(int(clockWaitInterval/time.Second)))
	command.Stdout, command.Stderr = os.Stdout, os.Stderr
	if err := command.Run(); err != nil {
		return fmt.Errorf("waiting for authenticated UTC: %w", errors.Join(ctx.Err(), err))
	}
	return nil
}
