package timequorum

import (
	"context"
	"errors"
	"testing"
	"time"
)

const monitorTestLimit = 5 * time.Second

type monitorResult struct {
	agreement Agreement
	err       error
}
type controlledSampler struct {
	requested chan struct{}
	results   chan monitorResult
}

func (sampler *controlledSampler) Poll(ctx context.Context) (Agreement, error) {
	select {
	case sampler.requested <- struct{}{}:
	case <-ctx.Done():
		return Agreement{}, ctx.Err()
	}
	select {
	case result := <-sampler.results:
		return result.agreement, result.err
	case <-ctx.Done():
		return Agreement{}, ctx.Err()
	}
}

type testFeed struct{}

func (testFeed) Send(context.Context, Agreement) error { return nil }

func TestMonitorArmsOnlyAfterQuorumAndClosesOnLoss(t *testing.T) {
	sampler := &controlledSampler{requested: make(chan struct{}, 1), results: make(chan monitorResult, 1)}
	monitor := NewMonitor(sampler, testFeed{}, t.Logf)
	if monitor.Healthy() || monitor.Arm() == nil {
		t.Fatal("unsynchronized monitor admitted traffic")
	}
	ctx, cancel := context.WithTimeout(context.Background(), monitorTestLimit)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- monitor.Run(ctx) }()
	select {
	case <-sampler.requested:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	now := time.Now()
	var samples []Sample
	for _, operator := range []Operator{Canonical, Cloudflare, Netnod} {
		samples = append(samples, Sample{Operator: operator, UTC: now.UTC(), Received: now, Radius: time.Millisecond})
	}
	agreement, err := Agree(samples, now)
	if err != nil {
		t.Fatal(err)
	}
	sampler.results <- monitorResult{agreement: agreement}
	select {
	case <-sampler.requested:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if !monitor.Healthy() {
		t.Fatal("authenticated quorum was not published")
	}
	if err := monitor.Arm(); err != nil {
		t.Fatal(err)
	}
	lost := errors.New("two operators remain")
	sampler.results <- monitorResult{err: lost}
	select {
	case err := <-done:
		if !errors.Is(err, lost) && !errors.Is(err, ErrQuorumUnavailable) {
			t.Fatalf("unexpected loss error: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("monitor did not terminate after runtime quorum loss")
	}
	if monitor.Healthy() {
		t.Fatal("failed quorum remained admissible")
	}
}

func TestMonitorExpiryClosesAdmissionWithoutPollCompletion(t *testing.T) {
	sampler := &controlledSampler{requested: make(chan struct{}, 1), results: make(chan monitorResult)}
	monitor := NewMonitor(sampler, testFeed{}, t.Logf)
	monitor.armed = true
	monitor.expires = time.Now().Add(-time.Nanosecond)
	ctx, cancel := context.WithTimeout(context.Background(), monitorTestLimit)
	defer cancel()
	if err := monitor.Run(ctx); !errors.Is(err, ErrQuorumUnavailable) {
		t.Fatalf("expiry error=%v", err)
	}
	if monitor.Healthy() {
		t.Fatal("expired quorum remained admissible")
	}
}
