package main

import (
	"sync"

	"golang.org/x/time/rate"
)

type RateLimiter struct {
	limits map[string]*rate.Limiter
	mu     *sync.RWMutex
	limit  rate.Limit
	burst  int
}

func NewRateLimiter(limit rate.Limit, burst int) *RateLimiter {
	i := &RateLimiter{
		limits: make(map[string]*rate.Limiter),
		mu:     &sync.RWMutex{},
		limit:  limit,
		burst:  burst,
	}

	return i
}

func (r *RateLimiter) Limit(key string) *rate.Limiter {
	r.mu.Lock()
	defer r.mu.Unlock()

	limiter, exists := r.limits[key]
	if !exists {
		r.limits[key] = rate.NewLimiter(r.limit, r.burst)
		return r.limits[key]
	}

	return limiter
}
