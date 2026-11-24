package key

import (
	"errors"
	"net/http"
	"strconv"
	"sync"
	"testing"
	"time"
)

type clock struct{ at time.Time }

func (c *clock) now() time.Time { return c.at }

func newTestCache(next Validator) (*Cache, *clock) {
	clock := &clock{at: time.Unix(1_700_000_000, 0)}
	cache := NewCache(next)
	cache.now = clock.now
	return cache, clock
}

func TestCacheAsksOncePerLifetime(t *testing.T) {
	var calls int
	cache, clock := newTestCache(stubValidator{called: &calls})
	req := Request{APIKey: "k", Path: "/v1/chat/completions"}

	for range 3 {
		if err := cache.Validate(req); err != nil {
			t.Fatalf("expected success, got %v", err)
		}
	}
	if calls != 1 {
		t.Fatalf("calls within the lifetime: got %d, want 1", calls)
	}

	clock.at = clock.at.Add(acceptedLifetime - time.Nanosecond)
	_ = cache.Validate(req)
	if calls != 1 {
		t.Fatalf("calls just before the lifetime ends: got %d, want 1", calls)
	}

	clock.at = clock.at.Add(time.Nanosecond)
	_ = cache.Validate(req)
	_ = cache.Validate(req)
	if calls != 2 {
		t.Fatalf("calls after the lifetime ended: got %d, want 2", calls)
	}
}

func TestCacheKeepsRequestsApart(t *testing.T) {
	var calls int
	cache, _ := newTestCache(stubValidator{called: &calls})
	requests := []Request{
		{APIKey: "k", Domain: "d", RequestedHost: "h", Path: "/a"},
		{APIKey: "other", Domain: "d", RequestedHost: "h", Path: "/a"},
		{APIKey: "k", Domain: "other", RequestedHost: "h", Path: "/a"},
		{APIKey: "k", Domain: "d", RequestedHost: "other", Path: "/a"},
		{APIKey: "k", Domain: "d", RequestedHost: "h", Path: "/other"},
	}
	for _, req := range requests {
		_ = cache.Validate(req)
		_ = cache.Validate(req)
	}
	if calls != len(requests) {
		t.Fatalf("calls: got %d, want one per distinct request (%d)", calls, len(requests))
	}
}

type switchValidator struct {
	err   error
	calls int
}

func (s *switchValidator) Validate(Request) error {
	s.calls++
	return s.err
}

func TestCacheNeverRemembersRefusalsOrFailures(t *testing.T) {
	refusal := &ValidationError{StatusCode: http.StatusUnauthorized}
	failure := errors.New("validation request failed")
	next := &switchValidator{}
	cache, clock := newTestCache(next)
	req := Request{APIKey: "k"}

	for _, err := range []error{refusal, failure} {
		next.err = err
		for range 2 {
			if got := cache.Validate(req); !errors.Is(got, err) {
				t.Fatalf("got %v, want %v", got, err)
			}
		}
	}
	if next.calls != 4 {
		t.Fatalf("calls while refused: got %d, want 4", next.calls)
	}

	next.err = nil
	_ = cache.Validate(req)
	next.err = refusal
	if err := cache.Validate(req); err != nil {
		t.Fatalf("an accepted request must hold for its lifetime, got %v", err)
	}

	clock.at = clock.at.Add(acceptedLifetime)
	for range 2 {
		if got := cache.Validate(req); !errors.Is(got, refusal) {
			t.Fatalf("after the lifetime: got %v, want the refusal", got)
		}
	}
	if next.calls != 7 {
		t.Fatalf("calls in all: got %d, want 7", next.calls)
	}
}

func TestCacheStaysBounded(t *testing.T) {
	cache, clock := newTestCache(stubValidator{})
	for i := range maxAccepted + 10 {
		_ = cache.Validate(Request{APIKey: strconv.Itoa(i)})
	}
	if len(cache.accepted) != maxAccepted {
		t.Fatalf("entries when full: got %d, want %d", len(cache.accepted), maxAccepted)
	}

	clock.at = clock.at.Add(acceptedLifetime)
	_ = cache.Validate(Request{APIKey: "new"})
	if len(cache.accepted) != 1 {
		t.Fatalf("entries after every older one lapsed: got %d, want 1", len(cache.accepted))
	}
}

func TestCacheIsSafeForConcurrentUse(t *testing.T) {
	cache := NewCache(&lockedValidator{})
	var group sync.WaitGroup
	for worker := range 8 {
		group.Add(1)
		go func() {
			defer group.Done()
			for i := range 200 {
				_ = cache.Validate(Request{APIKey: strconv.Itoa((worker + i) % 16)})
			}
		}()
	}
	group.Wait()
}

type lockedValidator struct{ mu sync.Mutex }

func (v *lockedValidator) Validate(Request) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	return nil
}
