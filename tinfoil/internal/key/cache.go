package key

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"
)

const (
	// acceptedLifetime is how long an accepted request is allowed again
	// without waiting for an answer. Each use asks again in the background,
	// so this only bounds how long a credential that is no longer checked
	// successfully, because it is idle or the checks fail, stays accepted.
	acceptedLifetime = 5 * time.Minute
	// maxAccepted bounds the memory the cache holds.
	maxAccepted = 10000
	// maxRechecks bounds the background checks running at once. A use that
	// finds them all busy is allowed without one.
	maxRechecks = 64
)

type requestID [sha256.Size]byte

type acceptance struct {
	until      time.Time
	rechecking bool
}

// Cache remembers the requests a Validator accepted, so a credential in
// steady use never waits for the Validator. Every use of a remembered
// request asks the Validator again in the background: a refusal forgets the
// request, so the next use waits for and receives the refusal, and an
// acceptance renews it. Requests that are not remembered are asked about
// before they proceed, and refusals and failures are never remembered.
type Cache struct {
	next     Validator
	now      func() time.Time
	rechecks chan struct{}
	pending  sync.WaitGroup

	mu       sync.Mutex
	accepted map[requestID]*acceptance
}

// NewCache returns a Validator that lets a request next accepted within
// acceptedLifetime proceed while next is asked again.
func NewCache(next Validator) *Cache {
	return &Cache{
		next:     next,
		now:      time.Now,
		rechecks: make(chan struct{}, maxRechecks),
		accepted: make(map[requestID]*acceptance),
	}
}

func (c *Cache) Validate(req Request) error {
	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshalling validation request: %w", err)
	}
	// Every field is part of the identity, so an acceptance for one host or
	// path never carries over to another.
	id := requestID(sha256.Sum256(body))
	if c.useAccepted(id, req) {
		return nil
	}
	if err := c.next.Validate(req); err != nil {
		return err
	}
	c.accept(id)
	return nil
}

// useAccepted reports whether the request is remembered, and starts a
// background check of it unless one is already running.
func (c *Cache) useAccepted(id requestID, req Request) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.accepted[id]
	if !ok {
		return false
	}
	if !c.now().Before(entry.until) {
		delete(c.accepted, id)
		return false
	}
	if !entry.rechecking {
		select {
		case c.rechecks <- struct{}{}:
			entry.rechecking = true
			c.pending.Add(1)
			go c.recheck(id, entry, req)
		default:
		}
	}
	return true
}

func (c *Cache) recheck(id requestID, entry *acceptance, req Request) {
	defer c.pending.Done()
	defer func() { <-c.rechecks }()
	err := c.next.Validate(req)

	c.mu.Lock()
	defer c.mu.Unlock()
	entry.rechecking = false
	switch {
	case err == nil:
		entry.until = c.now().Add(acceptedLifetime)
	case isRefusal(err):
		delete(c.accepted, id)
	}
	// A check that could not be made says nothing about the credential, so
	// the acceptance stands until its lifetime ends.
}

// isRefusal reports whether the error is the validator's verdict on the
// credential, as opposed to a check that failed to complete.
func isRefusal(err error) bool {
	var refusal *ValidationError
	return errors.As(err, &refusal) && refusal.StatusCode < http.StatusInternalServerError
}

func (c *Cache) accept(id requestID) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if len(c.accepted) >= maxAccepted {
		for other, entry := range c.accepted {
			if !now.Before(entry.until) {
				delete(c.accepted, other)
			}
		}
	}
	if len(c.accepted) >= maxAccepted {
		// Full of live entries: make room by forgetting any one of them,
		// which only costs that request a wait on its next use.
		for other := range c.accepted {
			delete(c.accepted, other)
			break
		}
	}
	c.accepted[id] = &acceptance{until: now.Add(acceptedLifetime)}
}
