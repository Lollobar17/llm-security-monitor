// Package ratelimit implements a per-IP token bucket rate limiter.
//
// The limiter maintains one bucket per source IP. Each bucket refills at a
// configurable rate (tokens/second) up to a configurable burst size.
// Buckets that have not been accessed for more than cleanupInterval are
// evicted to prevent unbounded memory growth.
//
// Zero external dependencies — uses only sync and time from stdlib.
package ratelimit

import (
	"math"
	"net/http"
	"sync"
	"time"
)

const cleanupInterval = 10 * time.Minute

// Limiter is a concurrent-safe per-IP token bucket rate limiter.
type Limiter struct {
	rps      float64 // tokens added per second
	burst    float64 // maximum tokens per bucket
	mu       sync.Mutex
	buckets  map[string]*bucket
	stopOnce sync.Once
	stop     chan struct{}
}

// New creates a Limiter allowing rps requests per second with a burst of
// burst requests. Call Stop() when the limiter is no longer needed.
func New(rps, burst float64) *Limiter {
	l := &Limiter{
		rps:     rps,
		burst:   burst,
		buckets: make(map[string]*bucket),
		stop:    make(chan struct{}),
	}
	go l.cleanup()
	return l
}

// Allow returns true if the given IP is within its rate limit.
func (l *Limiter) Allow(ip string) bool {
	l.mu.Lock()
	b, ok := l.buckets[ip]
	if !ok {
		b = &bucket{
			tokens:     l.burst,
			maxTokens:  l.burst,
			ratePerSec: l.rps,
			lastSeen:   time.Now(),
		}
		l.buckets[ip] = b
	}
	l.mu.Unlock()
	return b.allow()
}

// Middleware wraps an http.Handler and returns 429 when the rate limit is exceeded.
func (l *Limiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := extractIP(r)
		if !l.Allow(ip) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte(`{"error":"rate limit exceeded"}`)) //nolint:errcheck
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Stop halts the background cleanup goroutine.
func (l *Limiter) Stop() {
	l.stopOnce.Do(func() { close(l.stop) })
}

// Len returns the current number of tracked IPs (for metrics/testing).
func (l *Limiter) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}

// ── Token bucket ───────────────────────────────────────────────────────────────

type bucket struct {
	mu         sync.Mutex
	tokens     float64
	maxTokens  float64
	ratePerSec float64
	lastRefill time.Time
	lastSeen   time.Time
}

func (b *bucket) allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(b.lastRefill).Seconds()
	b.tokens = math.Min(b.maxTokens, b.tokens+elapsed*b.ratePerSec)
	b.lastRefill = now
	b.lastSeen   = now

	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

// ── Background cleanup ────────────────────────────────────────────────────────

func (l *Limiter) cleanup() {
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-l.stop:
			return
		case <-ticker.C:
			l.evictStale()
		}
	}
}

func (l *Limiter) evictStale() {
	cutoff := time.Now().Add(-cleanupInterval)
	l.mu.Lock()
	defer l.mu.Unlock()
	for ip, b := range l.buckets {
		b.mu.Lock()
		stale := b.lastSeen.Before(cutoff)
		b.mu.Unlock()
		if stale {
			delete(l.buckets, ip)
		}
	}
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func extractIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the leftmost (client) IP from the XFF chain
		for i := 0; i < len(xff); i++ {
			if xff[i] == ',' {
				return xff[:i]
			}
		}
		return xff
	}
	// Strip port from RemoteAddr
	addr := r.RemoteAddr
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			return addr[:i]
		}
	}
	return addr
}
