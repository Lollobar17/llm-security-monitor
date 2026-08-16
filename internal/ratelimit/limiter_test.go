package ratelimit_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Lollobar17/llm-security-monitor/internal/ratelimit"
)

func TestAllow_WithinLimit(t *testing.T) {
	l := ratelimit.New(10, 5) // 10 rps, burst 5
	defer l.Stop()

	for i := 0; i < 5; i++ {
		if !l.Allow("1.2.3.4") {
			t.Errorf("request %d should be allowed (within burst)", i+1)
		}
	}
	t.Log("✅ Within-burst requests all allowed")
}

func TestAllow_ExceedsBurst(t *testing.T) {
	l := ratelimit.New(1, 3) // 1 rps, burst 3
	defer l.Stop()

	allowed, denied := 0, 0
	for i := 0; i < 10; i++ {
		if l.Allow("1.2.3.4") {
			allowed++
		} else {
			denied++
		}
	}
	if allowed > 3 {
		t.Errorf("expected ≤3 allowed (burst), got %d", allowed)
	}
	if denied < 7 {
		t.Errorf("expected ≥7 denied, got %d", denied)
	}
	t.Logf("✅ Burst enforcement: allowed=%d denied=%d", allowed, denied)
}

func TestAllow_PerIP_Independence(t *testing.T) {
	l := ratelimit.New(1, 2) // burst of 2 per IP
	defer l.Stop()

	// IP A uses its 2 tokens
	l.Allow("10.0.0.1")
	l.Allow("10.0.0.1")
	if l.Allow("10.0.0.1") {
		t.Error("IP A's 3rd request should be denied")
	}

	// IP B has its own fresh bucket — should be allowed
	if !l.Allow("10.0.0.2") {
		t.Error("IP B's 1st request should be allowed (fresh bucket)")
	}
	t.Log("✅ Per-IP independence confirmed")
}

func TestAllow_Refill(t *testing.T) {
	l := ratelimit.New(100, 1) // 100 rps, burst 1
	defer l.Stop()

	// Drain the bucket
	l.Allow("5.5.5.5")
	if l.Allow("5.5.5.5") {
		t.Error("second immediate request should be denied")
	}

	// Wait long enough for refill (100 rps = 10 ms per token)
	time.Sleep(20 * time.Millisecond)

	if !l.Allow("5.5.5.5") {
		t.Error("request after refill should be allowed")
	}
	t.Log("✅ Token refill works correctly")
}

func TestMiddleware_Returns429(t *testing.T) {
	l := ratelimit.New(1, 1) // burst 1
	defer l.Stop()

	handler := l.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// First request — allowed
	r1 := httptest.NewRequest("POST", "/v1/chat/completions", nil)
	r1.RemoteAddr = "9.9.9.9:12345"
	w1 := httptest.NewRecorder()
	handler.ServeHTTP(w1, r1)
	if w1.Code != http.StatusOK {
		t.Errorf("first request: expected 200, got %d", w1.Code)
	}

	// Second request immediately — rate limited
	r2 := httptest.NewRequest("POST", "/v1/chat/completions", nil)
	r2.RemoteAddr = "9.9.9.9:12346"
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, r2)
	if w2.Code != http.StatusTooManyRequests {
		t.Errorf("second request: expected 429, got %d", w2.Code)
	}
	if w2.Header().Get("Retry-After") == "" {
		t.Error("expected Retry-After header on 429")
	}
	t.Logf("✅ Middleware: first=%d second=%d", w1.Code, w2.Code)
}

func TestLimiter_Cleanup(t *testing.T) {
	l := ratelimit.New(10, 10)
	defer l.Stop()

	l.Allow("192.168.1.1")
	l.Allow("192.168.1.2")
	l.Allow("192.168.1.3")

	if l.Len() != 3 {
		t.Errorf("expected 3 tracked IPs, got %d", l.Len())
	}
	t.Logf("✅ Limiter tracks %d IPs", l.Len())
}
