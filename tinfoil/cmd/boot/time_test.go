package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"tinfoil/internal/timeanchor"
)

type scriptedClockSource struct {
	failures int
	anchor   timeanchor.Anchor
	calls    int
}

func (source *scriptedClockSource) Acquire(context.Context) (timeanchor.Anchor, error) {
	source.calls++
	if source.calls <= source.failures {
		return timeanchor.Anchor{}, errors.New("timestamp authorities disagree")
	}
	return source.anchor, nil
}

func TestClockIsSetOnceAfterAuthoritiesAgree(t *testing.T) {
	authenticated := time.Date(2026, time.November, 13, 19, 15, 7, 0, time.UTC)
	source := &scriptedClockSource{failures: 2, anchor: timeanchor.Anchor{
		UTC: authenticated, Observed: time.Now(), Authorities: []string{"digicert", "sectigo"}}}
	var applied []time.Time
	detail, err := anchorClock(context.Background(), source, func(now time.Time) error {
		applied = append(applied, now)
		return nil
	}, time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if source.calls != 3 || len(applied) != 1 {
		t.Fatalf("acquired %d times and set the clock %d times", source.calls, len(applied))
	}
	if elapsed := applied[0].Sub(authenticated); elapsed < 0 || elapsed > time.Second {
		t.Fatalf("clock set %s from the authenticated time", elapsed)
	}
	if !strings.Contains(detail, "digicert, sectigo") {
		t.Fatalf("detail = %q", detail)
	}
}

func TestClockFailuresStopBoot(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	set := func(time.Time) error {
		t.Fatal("clock set without authenticated time")
		return nil
	}
	if _, err := anchorClock(ctx, &scriptedClockSource{failures: 1 << 30}, set, time.Millisecond); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("unanswered authorities returned %v", err)
	}

	denied := errors.New("operation not permitted")
	_, err := anchorClock(context.Background(), &scriptedClockSource{anchor: timeanchor.Anchor{Observed: time.Now()}},
		func(time.Time) error { return denied }, time.Millisecond)
	if !errors.Is(err, denied) {
		t.Fatalf("refused clock change returned %v", err)
	}
}
