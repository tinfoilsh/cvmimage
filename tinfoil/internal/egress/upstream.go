package egress

import (
	"context"
	"crypto/tls"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

const (
	maxIdleUpstreamConnections = 8
	// Short enough that reuse rarely meets a connection the resolver closed.
	upstreamIdleTimeout = 5 * time.Second
)

type idleConnection struct {
	*dns.Conn
	since time.Time
}

// upstream reuses authenticated connections and starts with the resolver
// address that answered last.
type upstream struct {
	client    *dns.Client
	addresses []string
	preferred atomic.Int32
	mu        sync.Mutex
	idle      map[string][]idleConnection
}

func newUpstream(addresses []string, config *tls.Config) *upstream {
	config = config.Clone()
	config.ClientSessionCache = tls.NewLRUClientSessionCache(0)
	return &upstream{
		client:    &dns.Client{Net: "tcp-tls", Timeout: upstreamTimeout, TLSConfig: config},
		addresses: addresses,
		idle:      make(map[string][]idleConnection),
	}
}

func (u *upstream) exchange(ctx context.Context, query *dns.Msg) (*dns.Msg, error) {
	first := int(u.preferred.Load())
	var lastErr error
	for i := range u.addresses {
		index := (first + i) % len(u.addresses)
		answer, err := u.exchangeWith(ctx, query, u.addresses[index])
		if err == nil && len(answer.Question) == 1 &&
			dns.CanonicalName(answer.Question[0].Name) == dns.CanonicalName(query.Question[0].Name) &&
			answer.Question[0].Qtype == query.Question[0].Qtype && answer.Question[0].Qclass == dns.ClassINET && !answer.Truncated {
			u.preferred.Store(int32(index))
			return answer, nil
		}
		lastErr = fmt.Errorf("invalid or unavailable upstream DNS answer: %v", err)
	}
	return nil, lastErr
}

func (u *upstream) exchangeWith(ctx context.Context, query *dns.Msg, address string) (*dns.Msg, error) {
	for {
		connection, reused := u.take(address)
		if !reused {
			var err error
			if connection, err = u.client.DialContext(ctx, address); err != nil {
				return nil, err
			}
		}
		answer, _, err := u.client.ExchangeWithConnContext(ctx, query, connection)
		if err == nil {
			u.put(address, connection)
			return answer, nil
		}
		// A failed connection may still deliver this query's answer later, so
		// it is never reused.
		connection.Close()
		if !reused || ctx.Err() != nil {
			return nil, err
		}
	}
}

func (u *upstream) take(address string) (*dns.Conn, bool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	for idle := u.idle[address]; len(idle) > 0; idle = u.idle[address] {
		last := idle[len(idle)-1]
		u.idle[address] = idle[:len(idle)-1]
		if time.Since(last.since) < upstreamIdleTimeout {
			return last.Conn, true
		}
		last.Close()
	}
	return nil, false
}

func (u *upstream) put(address string, connection *dns.Conn) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if len(u.idle[address]) >= maxIdleUpstreamConnections {
		connection.Close()
		return
	}
	u.idle[address] = append(u.idle[address], idleConnection{connection, time.Now()})
}
