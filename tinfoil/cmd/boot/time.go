package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"tinfoil/internal/boot"
	"tinfoil/internal/timeanchor"
)

const (
	clockBootstrapLimit = 5 * time.Minute
	clockRetryInterval  = 5 * time.Second
)

type clockSource interface {
	Acquire(context.Context) (timeanchor.Anchor, error)
}

func anchorGuestClock(ctx context.Context) (string, error) {
	authorities, err := timeanchor.PinnedAuthorities()
	if err != nil {
		return "", err
	}
	source, err := timeanchor.NewClient(boot.TimeRelayURL, authorities)
	if err != nil {
		return "", err
	}
	return anchorClock(ctx, source, setSystemClock, clockRetryInterval)
}

// anchorClock sets UTC once from authenticated timestamps. Nothing adjusts the
// clock afterward, so later readings are this anchor plus protected elapsed time.
func anchorClock(parent context.Context, source clockSource, set func(time.Time) error, retry time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(parent, clockBootstrapLimit)
	defer cancel()
	ticker := time.NewTicker(retry)
	defer ticker.Stop()
	for {
		anchor, err := source.Acquire(ctx)
		if err == nil {
			if err := set(anchor.Now()); err != nil {
				return "", fmt.Errorf("setting the clock: %w", err)
			}
			return "UTC anchored by " + strings.Join(anchor.Authorities, ", "), nil
		}
		log.Printf("Authenticated time: %v", err)
		select {
		case <-ctx.Done():
			return "", fmt.Errorf("waiting for authenticated UTC: %w", errors.Join(ctx.Err(), err))
		case <-ticker.C:
		}
	}
}

func setSystemClock(now time.Time) error {
	value := unix.NsecToTimespec(now.UnixNano())
	return unix.ClockSettime(unix.CLOCK_REALTIME, &value)
}
