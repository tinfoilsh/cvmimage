package attestationmaterial

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math/rand/v2"
	"slices"
	"sync"
	"time"

	wire "github.com/tinfoilsh/tinfoil-go/verifier/collaterals"
	"github.com/tinfoilsh/tinfoil-go/verifier/envelope"
)

const (
	defaultRefreshBefore = 4 * time.Hour
	defaultRefreshJitter = time.Hour
	defaultRetryMin      = time.Minute
	defaultRetryMax      = 30 * time.Minute
	defaultRefreshCap    = 24 * time.Hour
)

var ErrUnavailable = errors.New("attestation collateral unavailable")

type Fetcher interface {
	Fetch(context.Context, wire.Request) (wire.Response, error)
}

type Manager struct {
	mu       sync.RWMutex
	response wire.Response
	request  wire.Request
	fetcher  Fetcher
	path     string
	now      func() time.Time
	jitter   func(time.Duration) time.Duration

	refreshBefore time.Duration
	retryMin      time.Duration
	retryMax      time.Duration
	refreshCap    time.Duration
}

func NewManager(initial wire.Response, request wire.Request, fetcher Fetcher, path string) *Manager {
	return &Manager{
		response:      initial,
		request:       request,
		fetcher:       fetcher,
		path:          path,
		now:           time.Now,
		jitter:        randomDuration,
		refreshBefore: defaultRefreshBefore,
		retryMin:      defaultRetryMin,
		retryMax:      defaultRetryMax,
		refreshCap:    defaultRefreshCap,
	}
}

func (m *Manager) Current() ([]envelope.CollateralEntry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if !m.managed() {
		return slices.Clone(m.response.Collateral), nil
	}
	if m.response.ExpiresAt.IsZero() || !m.now().Before(m.response.ExpiresAt) {
		return nil, fmt.Errorf("%w: cache expired at %s", ErrUnavailable, m.response.ExpiresAt.Format(time.RFC3339))
	}
	return slices.Clone(m.response.Collateral), nil
}

func (m *Manager) Run(ctx context.Context) {
	if !m.managed() {
		return
	}
	retry := m.retryMin
	for {
		delay := m.nextRefreshDelay()
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}

		if err := m.Refresh(ctx); err != nil {
			log.Printf("Attestation collateral refresh failed: %v; retrying in %s", err, retry)
			if !sleep(ctx, retry) {
				return
			}
			retry = min(retry*2, m.retryMax)
			continue
		}
		retry = m.retryMin
	}
}

func (m *Manager) Refresh(ctx context.Context) error {
	if !m.managed() {
		return fmt.Errorf("%w: refresh is not configured", ErrUnavailable)
	}
	response, err := m.fetcher.Fetch(ctx, m.request)
	if err != nil {
		return err
	}
	if !m.now().Before(response.ExpiresAt) {
		return fmt.Errorf("received already-expired collateral cache (expires_at %s)", response.ExpiresAt.Format(time.RFC3339))
	}
	if m.path != "" {
		if err := WriteJSON(m.path, response); err != nil {
			return fmt.Errorf("persisting refreshed collateral: %w", err)
		}
	}

	m.mu.Lock()
	m.response = response
	m.mu.Unlock()
	log.Printf("Attestation collateral refreshed; expires at %s (%d entries)", response.ExpiresAt.Format(time.RFC3339), len(response.Collateral))
	return nil
}

func (m *Manager) managed() bool {
	return m.fetcher != nil && m.request.Repo != "" && m.request.Platform != "" && m.request.Platform != "dummy"
}

func (m *Manager) nextRefreshDelay() time.Duration {
	m.mu.RLock()
	expiresAt := m.response.ExpiresAt
	m.mu.RUnlock()
	if expiresAt.IsZero() {
		return 0
	}
	remaining := expiresAt.Sub(m.now())
	if remaining <= 0 {
		return 0
	}
	lead := m.refreshBefore + m.jitter(defaultRefreshJitter)
	lead = min(lead, remaining/2)
	delay := remaining - lead
	return min(max(delay, 0), m.refreshCap)
}

func randomDuration(limit time.Duration) time.Duration {
	if limit <= 0 {
		return 0
	}
	return time.Duration(rand.Int64N(int64(limit)))
}

func sleep(ctx context.Context, duration time.Duration) bool {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
