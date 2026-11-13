package main

import (
	"context"
	"net"
	"os"
	"time"

	"tinfoil/internal/boot"
)

const timeFeedReadyLimit = 30 * time.Second

func newTimeFeed(ctx context.Context) (*os.File, error) {
	if err := endpointReady("unixgram", boot.ChronyFeedSocketPath, timeFeedReadyLimit)(ctx); err != nil {
		return nil, err
	}
	connection, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: boot.ChronyFeedSocketPath, Net: "unixgram"})
	if err != nil {
		return nil, err
	}
	defer connection.Close()
	return connection.File()
}
