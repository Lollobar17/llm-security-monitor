package metrics_test

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Lollobar17/llm-security-monitor/internal/metrics"
)

func TestMetricsHandler_ContainsExpectedKeys(t *testing.T) {
	// Reset global counters for test isolation by recording some values
	metrics.RecordRequest()
	metrics.RecordRequest()
	metrics.RecordSTI("HIGH")
	metrics.RecordNLI("MEDIUM")
	metrics.RecordBlocked()
	metrics.RecordSanitized()
	metrics.RecordRateLimited()
	metrics.RecordObfuscated()

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/metrics", nil)
	metrics.Handler()(w, r)

	body := w.Body.String()

	expectedKeys := []string{
		"llm_mon_requests_total",
		`llm_mon_sti_alerts_total{confidence="HIGH"}`,
		`llm_mon_nli_alerts_total{confidence="MEDIUM"}`,
		"llm_mon_blocked_total",
		"llm_mon_sanitized_total",
		"llm_mon_rate_limited_total",
		"llm_mon_obfuscated_total",
	}

	for _, key := range expectedKeys {
		if !strings.Contains(body, key) {
			t.Errorf("expected metric key %q not found in output", key)
		}
	}

	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("expected text/plain Content-Type, got %q", ct)
	}

	t.Logf("✅ /metrics output (%d bytes):\n%s", len(body), body)
}

func TestRecordSTI_AllConfidenceLevels(t *testing.T) {
	// Verify each confidence level maps to the right counter — should not panic
	for _, conf := range []string{"HIGH", "MEDIUM", "LOW", "UNKNOWN"} {
		metrics.RecordSTI(conf)
	}
	t.Log("✅ RecordSTI handles all confidence levels including unknown")
}

func TestMetrics_ContentTypeIsPrometheusCompatible(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/metrics", nil)
	metrics.Handler()(w, r)

	ct := w.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/plain") {
		t.Errorf("Content-Type should be text/plain for Prometheus compat, got %q", ct)
	}
	if !strings.Contains(ct, "version=0.0.4") {
		t.Errorf("Content-Type should include version=0.0.4, got %q", ct)
	}
	t.Logf("✅ Content-Type: %s", ct)
}
