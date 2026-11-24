package key

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

const (
	// acceptedLifetime is how long an accepted request is allowed again
	// without asking. A credential that is revoked, expires, or runs out of
	// quota keeps working here for at most this long.
	acceptedLifetime = time.Minute
	// maxAccepted bounds the memory the cache holds.
	maxAccepted = 10000
)

// Cache remembers the requests a Validator accepted, so a credential in
// steady use is checked once per acceptedLifetime instead of on every
// request. Refusals and failures are never remembered.
type Cache struct {
	next Validator
	now  func() time.Time

	mu       sync.Mutex
	accepted map[[sha256.Size]byte]time.Time
}

// NewCache returns a Validator that consults next only for requests it has
// not accepted within acceptedLifetime.
func NewCache(next Validator) *Cache {
	return &Cache{
		next:     next,
		now:      time.Now,
		accepted: make(map[[sha256.Size]byte]time.Time),
	}
}

func (c *Cache) Validate(req Request) error {
	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshalling validation request: %w", err)
	}
	// Every field is part of the identity, so an acceptance for one host or
	// path never carries over to another.
	id := sha256.Sum256(body)
	if c.isAccepted(id) {
		return nil
	}
	if err := c.next.Validate(req); err != nil {
		return err
	}
	c.accept(id)
	return nil
}

func (c *Cache) isAccepted(id [sha256.Size]byte) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	until, ok := c.accepted[id]
	if !ok {
		return false
	}
	if c.now().Before(until) {
		return true
	}
	delete(c.accepted, id)
	return false
}

func (c *Cache) accept(id [sha256.Size]byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if len(c.accepted) >= maxAccepted {
		for other, until := range c.accepted {
			if !now.Before(until) {
				delete(c.accepted, other)
			}
		}
	}
	if len(c.accepted) >= maxAccepted {
		// Full of live entries: make room by forgetting any one of them,
		// which only costs that request its next check.
		for other := range c.accepted {
			delete(c.accepted, other)
			break
		}
	}
	c.accepted[id] = now.Add(acceptedLifetime)
}
