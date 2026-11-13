package timequorum

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"tinfoil/internal/ntsrelay"
)

const (
	PollInterval          = 64 * time.Second
	FeedLimit             = 2 * time.Second
	QuorumLifetime        = PollInterval + ntsrelay.ExchangeLimit + FeedLimit
	startupSampleInterval = 2 * time.Second
	startupRetryInterval  = 8 * time.Second
)

var ErrQuorumUnavailable = errors.New("authenticated time quorum is unavailable")

type timeSampler interface {
	Poll(context.Context) (Agreement, error)
}
type timeFeed interface {
	Send(context.Context, Agreement) error
}

// Monitor keeps admission state in memory. Its deadline uses local monotonic
// time and is anchored to the oldest authenticated response in the quorum.
type Monitor struct {
	sampler   timeSampler
	feed      timeFeed
	log       func(string, ...any)
	mu        sync.Mutex
	expires   time.Time
	armed     bool
	ready     bool
	lastError error
	changed   chan struct{}
}

func NewMonitor(sampler timeSampler, feed timeFeed, log func(string, ...any)) *Monitor {
	return &Monitor{sampler: sampler, feed: feed, log: log, changed: make(chan struct{}, 1)}
}

func (monitor *Monitor) Healthy() bool {
	monitor.mu.Lock()
	defer monitor.mu.Unlock()
	return monitor.ready && time.Now().Before(monitor.expires)
}

// Resume requires fresh quorum after a service restart while preserving the
// runtime failure policy. Admission stays closed during reacquisition.
func (monitor *Monitor) Resume() {
	monitor.mu.Lock()
	defer monitor.mu.Unlock()
	monitor.armed = true
	monitor.ready = false
	monitor.expires = time.Now().Add(ntsrelay.ExchangeLimit + FeedLimit)
	monitor.notify()
}

func (monitor *Monitor) Arm() error {
	monitor.mu.Lock()
	defer monitor.mu.Unlock()
	if !monitor.ready || !time.Now().Before(monitor.expires) {
		return errors.Join(ErrQuorumUnavailable, monitor.lastError)
	}
	monitor.armed = true
	monitor.notify()
	return nil
}

func (monitor *Monitor) notify() {
	select {
	case monitor.changed <- struct{}{}:
	default:
	}
}

func (monitor *Monitor) Run(parent context.Context) error {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- monitor.poll(ctx) }()
	for {
		monitor.mu.Lock()
		armed, expires, lastError := monitor.armed, monitor.expires, monitor.lastError
		monitor.mu.Unlock()
		var timer *time.Timer
		var deadline <-chan time.Time
		if armed {
			if !time.Now().Before(expires) {
				return errors.Join(ErrQuorumUnavailable, lastError)
			}
			timer = time.NewTimer(time.Until(expires))
			deadline = timer.C
		}
		select {
		case err := <-done:
			if timer != nil {
				timer.Stop()
			}
			return err
		case <-parent.Done():
			if timer != nil {
				timer.Stop()
			}
			return parent.Err()
		case <-monitor.changed:
			if timer != nil {
				timer.Stop()
			}
		case <-deadline:
		}
	}
}

func (monitor *Monitor) poll(ctx context.Context) error {
	for {
		started := time.Now()
		agreement, err := monitor.sampler.Poll(ctx)
		if err == nil {
			err = monitor.feed.Send(ctx, agreement)
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		monitor.mu.Lock()
		if err == nil && !agreement.oldest.IsZero() {
			monitor.expires = agreement.oldest.Add(QuorumLifetime)
			monitor.ready = true
			monitor.lastError = nil
		} else {
			if err == nil {
				err = errors.New("time agreement has no authenticated receipt time")
			}
			monitor.expires = time.Time{}
			monitor.ready = false
			monitor.lastError = err
		}
		armed := monitor.armed
		monitor.mu.Unlock()
		monitor.notify()
		if err != nil {
			monitor.log("Authenticated time: %v", err)
			if armed {
				return fmt.Errorf("runtime time quorum lost: %w", err)
			}
		}
		interval := startupSampleInterval
		if err != nil {
			interval = startupRetryInterval
		} else if armed {
			interval = PollInterval
		}
		timer := time.NewTimer(max(0, time.Until(started.Add(interval))))
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}
