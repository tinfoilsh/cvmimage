package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"time"

	"tinfoil/internal/boot"
)

func synchronizeClock(parent context.Context, client string) error {
	ctx, cancel := context.WithTimeout(parent, clockBootstrapLimit)
	defer cancel()
	if err := waitForClock(ctx, client); err != nil {
		return err
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", boot.AttestationSocket)
	}}
	defer transport.CloseIdleConnections()
	if err := armTimeQuorum(ctx, &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}); err != nil {
		return err
	}
	return waitForClock(ctx, client)
}

func armTimeQuorum(ctx context.Context, client *http.Client) error {
	ticker := time.NewTicker(clockWaitInterval)
	defer ticker.Stop()
	for {
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://localhost"+boot.TimeReadyPath, nil)
		if err != nil {
			return err
		}
		response, err := client.Do(request)
		if err == nil {
			response.Body.Close()
			if response.StatusCode == http.StatusNoContent {
				return nil
			}
			if response.StatusCode != http.StatusServiceUnavailable {
				return fmt.Errorf("time readiness returned HTTP %d", response.StatusCode)
			}
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("waiting for time quorum: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}

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
