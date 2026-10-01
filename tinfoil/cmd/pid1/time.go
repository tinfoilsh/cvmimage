package main

import (
	"context"
	"errors"
	"io"
	"os"

	"golang.org/x/sys/unix"

	"tinfoil/internal/pid1/supervisor"
	"tinfoil/internal/trustedtime"
)

const (
	chronycPath         = "/usr/bin/chronyc"
	trackingOutputLimit = 4096
)

func queryTime(ctx context.Context, run func(context.Context, supervisor.Command) error) ([]byte, error) {
	fd, err := unix.MemfdCreate("chrony-tracking", unix.MFD_CLOEXEC)
	if err != nil {
		return nil, err
	}
	output := os.NewFile(uintptr(fd), "chrony-tracking")
	defer output.Close()
	query := command("chronyc", chronycPath, "-u", "root", "-n", "-c", "-h", trustedtime.SocketPath, "tracking")
	query.Env = []string{"LC_ALL=C"}
	query.Stdout = output
	if err := run(ctx, query); err != nil {
		return nil, err
	}
	// A file avoids waiting for pipe EOF from a surviving child. The manager
	// owns the exit status and terminates descendants before returning.
	data := make([]byte, trackingOutputLimit+1)
	n, err := output.ReadAt(data, 0)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if n > trackingOutputLimit {
		return nil, errors.New("time query output exceeded its limit")
	}
	return data[:n], nil
}
