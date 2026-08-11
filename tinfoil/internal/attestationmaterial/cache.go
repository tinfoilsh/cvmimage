package attestationmaterial

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	wire "github.com/tinfoilsh/tinfoil-go/verifier/collaterals"
	"github.com/tinfoilsh/tinfoil-go/verifier/envelope"
)

const (
	refreshBefore  = 24 * time.Hour
	retryAfter     = time.Minute
	refreshTimeout = 35 * time.Second
)

var ErrUnavailable = errors.New("attestation collateral unavailable")

type Fetcher interface {
	Fetch(context.Context, wire.Request) (wire.Response, error)
}

type Cache struct {
	mu           sync.Mutex
	response     *wire.Response
	refreshing   chan struct{}
	nextAttempt  time.Time
	request      wire.Request
	fetcher      Fetcher
	now          func() time.Time
	refreshAfter time.Duration
	retryAfter   time.Duration
}

func NewCache(request wire.Request, fetcher Fetcher) *Cache {
	return &Cache{
		request:      request,
		fetcher:      fetcher,
		now:          time.Now,
		refreshAfter: refreshBefore,
		retryAfter:   retryAfter,
	}
}

func (c *Cache) Current(ctx context.Context) ([]envelope.CollateralEntry, error) {
	for {
		c.mu.Lock()
		now := c.now()
		if c.response != nil && now.Before(c.response.ExpiresAt) {
			collateral := cloneCollateral(c.response.Collateral)
			if c.refreshing == nil && !now.Before(c.nextAttempt) {
				c.startRefresh()
			}
			c.mu.Unlock()
			return collateral, nil
		}
		if c.refreshing != nil {
			done := c.refreshing
			c.mu.Unlock()
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-done:
				continue
			}
		}
		if now.Before(c.nextAttempt) {
			nextAttempt := c.nextAttempt
			c.mu.Unlock()
			return nil, fmt.Errorf("%w: refresh retry available at %s", ErrUnavailable, nextAttempt.Format(time.RFC3339))
		}
		done := c.startRefresh()
		c.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-done:
		}
	}
}

func (c *Cache) startRefresh() chan struct{} {
	done := make(chan struct{})
	c.refreshing = done
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), refreshTimeout)
		defer cancel()
		if err := c.refresh(ctx, done); err != nil {
			log.Printf("Attestation collateral refresh failed: %v", err)
		}
	}()
	return done
}

func (c *Cache) refresh(ctx context.Context, done chan struct{}) error {
	response, err := c.fetcher.Fetch(ctx, c.request)
	now := c.now()
	if err == nil && !now.Before(response.ExpiresAt) {
		err = fmt.Errorf("received expired collateral (expires_at %s)", response.ExpiresAt.Format(time.RFC3339))
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if err != nil {
		c.nextAttempt = now.Add(c.retryAfter)
	} else {
		c.response = &response
		remaining := response.ExpiresAt.Sub(now)
		c.nextAttempt = response.ExpiresAt.Add(-min(c.refreshAfter, remaining/2))
	}
	c.refreshing = nil
	close(done)
	return err
}

func cloneCollateral(entries []envelope.CollateralEntry) []envelope.CollateralEntry {
	cloned := make([]envelope.CollateralEntry, len(entries))
	for index, entry := range entries {
		cloned[index] = entry
		cloned[index].Data = bytes.Clone(entry.Data)
		cloned[index].Subjects = append([]string(nil), entry.Subjects...)
	}
	return cloned
}
