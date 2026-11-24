package key

import (
	"errors"
	"net/http"
	"strconv"
	"sync"
	"testing"
	"time"
)

type clock struct {
	mu sync.Mutex
	at time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.at
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.at = c.at.Add(d)
}

// scriptedValidator answers with whatever the test last set, counts its
// calls, and can hold every call until the test releases it.
type scriptedValidator struct {
	mu    sync.Mutex
	err   error
	calls int
	hold  chan struct{}
}

func (s *scriptedValidator) Validate(Request) error {
	s.mu.Lock()
	s.calls++
	err, hold := s.err, s.hold
	s.mu.Unlock()
	if hold != nil {
		<-hold
	}
	return err
}

func (s *scriptedValidator) answer(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.err = err
}

func (s *scriptedValidator) holdCalls() (release func()) {
	hold := make(chan struct{})
	s.mu.Lock()
	s.hold = hold
	s.mu.Unlock()
	return func() {
		s.mu.Lock()
		s.hold = nil
		s.mu.Unlock()
		close(hold)
	}
}

func (s *scriptedValidator) called() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

func (s *scriptedValidator) waitForCalls(t *testing.T, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for s.called() < want {
		if time.Now().After(deadline) {
			t.Fatalf("calls: got %d, want %d", s.called(), want)
		}
		time.Sleep(time.Millisecond)
	}
}

func newTestCache() (*Cache, *scriptedValidator, *clock) {
	next := &scriptedValidator{}
	clock := &clock{at: time.Unix(1_700_000_000, 0)}
	cache := NewCache(next)
	cache.now = clock.now
	return cache, next, clock
}

func mustAccept(t *testing.T, cache *Cache, req Request) {
	t.Helper()
	if err := cache.Validate(req); err != nil {
		t.Fatalf("expected the request to be accepted, got %v", err)
	}
}

var (
	errRefused     = &ValidationError{StatusCode: http.StatusUnauthorized}
	errUnavailable = &ValidationError{StatusCode: http.StatusServiceUnavailable}
	errUnreachable = errors.New("validation request failed")
)

func TestCacheAcceptedRequestDoesNotWait(t *testing.T) {
	cache, next, _ := newTestCache()
	req := Request{APIKey: "k", Path: "/v1/chat/completions"}
	mustAccept(t, cache, req)
	if next.called() != 1 {
		t.Fatalf("the first use must be checked before it proceeds: %d calls", next.called())
	}

	release := next.holdCalls()
	for range 5 {
		mustAccept(t, cache, req)
	}
	next.waitForCalls(t, 2)
	if next.called() != 2 {
		t.Fatalf("uses during a background check must not start another: %d calls", next.called())
	}
	release()
	cache.pending.Wait()

	mustAccept(t, cache, req)
	cache.pending.Wait()
	if next.called() != 3 {
		t.Fatalf("each later use is checked in the background: %d calls", next.called())
	}
}

func TestCacheRefusalForgetsTheRequest(t *testing.T) {
	cache, next, _ := newTestCache()
	req := Request{APIKey: "k"}
	mustAccept(t, cache, req)

	next.answer(errRefused)
	mustAccept(t, cache, req)
	cache.pending.Wait()

	for range 2 {
		if err := cache.Validate(req); !errors.Is(err, errRefused) {
			t.Fatalf("after a refused check: got %v, want the refusal", err)
		}
	}
	cache.pending.Wait()
	if next.called() != 4 {
		t.Fatalf("a refused request is asked about on every use: %d calls", next.called())
	}
}

func TestCacheFailedCheckKeepsTheRequestUntilItsLifetimeEnds(t *testing.T) {
	for _, failure := range []error{errUnavailable, errUnreachable} {
		cache, next, clock := newTestCache()
		req := Request{APIKey: "k"}
		mustAccept(t, cache, req)

		next.answer(failure)
		clock.advance(acceptedLifetime - time.Second)
		mustAccept(t, cache, req)
		cache.pending.Wait()
		mustAccept(t, cache, req)
		cache.pending.Wait()

		clock.advance(time.Second)
		if err := cache.Validate(req); !errors.Is(err, failure) {
			t.Fatalf("after the lifetime: got %v, want %v", err, failure)
		}
	}
}

func TestCacheAcceptedCheckRenewsTheRequest(t *testing.T) {
	cache, next, clock := newTestCache()
	req := Request{APIKey: "k"}
	mustAccept(t, cache, req)

	clock.advance(acceptedLifetime - time.Second)
	mustAccept(t, cache, req)
	cache.pending.Wait()

	// Past the first acceptance's lifetime, within the renewed one: a use
	// proceeds even while the validator does not answer.
	clock.advance(acceptedLifetime - time.Second)
	release := next.holdCalls()
	mustAccept(t, cache, req)
	release()
	cache.pending.Wait()
}

func TestCacheIdleRequestIsCheckedBeforeItProceeds(t *testing.T) {
	cache, next, clock := newTestCache()
	req := Request{APIKey: "k"}
	mustAccept(t, cache, req)

	clock.advance(acceptedLifetime)
	next.answer(errRefused)
	if err := cache.Validate(req); !errors.Is(err, errRefused) {
		t.Fatalf("after an idle lifetime: got %v, want the refusal", err)
	}
}

func TestCacheKeepsRequestsApart(t *testing.T) {
	cache, next, _ := newTestCache()
	mustAccept(t, cache, Request{APIKey: "k", Domain: "d", RequestedHost: "h", Path: "/a"})

	next.answer(errRefused)
	for _, req := range []Request{
		{APIKey: "other", Domain: "d", RequestedHost: "h", Path: "/a"},
		{APIKey: "k", Domain: "other", RequestedHost: "h", Path: "/a"},
		{APIKey: "k", Domain: "d", RequestedHost: "other", Path: "/a"},
		{APIKey: "k", Domain: "d", RequestedHost: "h", Path: "/other"},
	} {
		if err := cache.Validate(req); !errors.Is(err, errRefused) {
			t.Fatalf("%+v: got %v, want the refusal", req, err)
		}
	}
}

func TestCacheNeverRemembersRefusalsOrFailures(t *testing.T) {
	cache, next, _ := newTestCache()
	req := Request{APIKey: "k"}
	for _, err := range []error{errRefused, errUnavailable, errUnreachable} {
		next.answer(err)
		for range 2 {
			if got := cache.Validate(req); !errors.Is(got, err) {
				t.Fatalf("got %v, want %v", got, err)
			}
		}
	}
	if next.called() != 6 {
		t.Fatalf("calls: got %d, want 6", next.called())
	}
}

func TestCacheStaysBounded(t *testing.T) {
	cache, _, clock := newTestCache()
	for i := range maxAccepted + 10 {
		mustAccept(t, cache, Request{APIKey: strconv.Itoa(i)})
	}
	if len(cache.accepted) != maxAccepted {
		t.Fatalf("entries when full: got %d, want %d", len(cache.accepted), maxAccepted)
	}

	clock.advance(acceptedLifetime)
	mustAccept(t, cache, Request{APIKey: "new"})
	if len(cache.accepted) != 1 {
		t.Fatalf("entries after every older one lapsed: got %d, want 1", len(cache.accepted))
	}
}

func TestCacheBoundsBackgroundChecks(t *testing.T) {
	cache, next, _ := newTestCache()
	const requests = maxRechecks + 5
	for i := range requests {
		mustAccept(t, cache, Request{APIKey: strconv.Itoa(i)})
	}

	release := next.holdCalls()
	for i := range requests {
		mustAccept(t, cache, Request{APIKey: strconv.Itoa(i)})
	}
	next.waitForCalls(t, requests+maxRechecks)
	release()
	cache.pending.Wait()
	if next.called() != requests+maxRechecks {
		t.Fatalf("background checks: got %d, want %d", next.called()-requests, maxRechecks)
	}
}

func TestCacheIsSafeForConcurrentUse(t *testing.T) {
	cache, next, _ := newTestCache()
	var group sync.WaitGroup
	for worker := range 8 {
		group.Add(1)
		go func() {
			defer group.Done()
			for i := range 200 {
				if i == 100 && worker == 0 {
					next.answer(errRefused)
				}
				_ = cache.Validate(Request{APIKey: strconv.Itoa((worker + i) % 16)})
			}
		}()
	}
	group.Wait()
	cache.pending.Wait()
}
