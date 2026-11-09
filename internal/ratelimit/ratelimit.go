// Package ratelimit is a tiny in-memory token bucket keyed by an arbitrary string (client
// IP for registration, key id for sending). It is sufficient for a single-instance relay;
// a multi-instance deployment would move this to a shared store.
package ratelimit

import (
	"sync"
	"time"
)

// Limiter refills each bucket at a fixed rate up to a burst ceiling.
type Limiter struct {
	mu        sync.Mutex
	buckets   map[string]*bucket
	rate      float64 // tokens per second
	burst     float64
	lastEvict time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

// evictInterval is how often idle buckets are swept. Driven by elapsed time rather than a
// call counter so an idle relay still releases memory.
const evictInterval = 5 * time.Minute

// New builds a Limiter that refills perMinute tokens per minute, up to burst.
func New(perMinute float64, burst int) *Limiter {
	return &Limiter{
		buckets:   make(map[string]*bucket),
		rate:      perMinute / 60.0,
		burst:     float64(burst),
		lastEvict: time.Now(),
	}
}

// Allow reports whether an action for key may proceed, consuming one token if so.
func (l *Limiter) Allow(key string) bool { return l.AllowN(key, 1) }

// Peek reports whether key has a token left, without consuming one.
func (l *Limiter) Peek(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[key]
	if !ok {
		return l.burst >= 1
	}
	return b.tokens+time.Since(b.last).Seconds()*l.rate >= 1
}

// AllowN consumes n tokens at once, or none: a request that does not fit leaves the bucket
// untouched, so a flood of oversized requests cannot drain a budget it is never granted.
func (l *Limiter) AllowN(key string, n int) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if now.Sub(l.lastEvict) > evictInterval {
		l.evictIdle(now)
		l.lastEvict = now
	}
	need := float64(n)
	b, ok := l.buckets[key]
	if !ok {
		if need > l.burst {
			return false
		}
		l.buckets[key] = &bucket{tokens: l.burst - need, last: now}
		return true
	}
	b.tokens += now.Sub(b.last).Seconds() * l.rate
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.last = now
	if b.tokens >= need {
		b.tokens -= need
		return true
	}
	return false
}

// evictIdle removes buckets untouched for 10 minutes. Must be called with l.mu held.
func (l *Limiter) evictIdle(now time.Time) {
	cutoff := now.Add(-10 * time.Minute)
	for k, b := range l.buckets {
		if b.last.Before(cutoff) {
			delete(l.buckets, k)
		}
	}
}
