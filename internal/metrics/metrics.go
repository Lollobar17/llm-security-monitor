// Package metrics implements a Prometheus-compatible metrics collector.
//
// Exposes counters for requests, detections, blocks, sanitizations, and
// rate-limit hits via a /metrics endpoint in the Prometheus text exposition
// format. Zero external dependencies — all atomic operations via sync/atomic.
//
// Compatible with Prometheus scraping and the Grafana dashboard in
// Homelab_SIEM (prometheus.yml: add job llm-security-monitor).
package metrics

import (
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
)

// Collector holds all metric counters.
type Collector struct {
	RequestsTotal     atomic.Int64
	STIHighTotal      atomic.Int64
	STIMediumTotal    atomic.Int64
	STILowTotal       atomic.Int64
	NLIHighTotal      atomic.Int64
	NLIMediumTotal    atomic.Int64
	NLILowTotal       atomic.Int64
	BlockedTotal      atomic.Int64
	SanitizedTotal    atomic.Int64
	RateLimitedTotal  atomic.Int64
	ObfuscatedTotal   atomic.Int64
}

// Global is the process-wide metrics instance.
var Global = &Collector{}

// ── Recording helpers ──────────────────────────────────────────────────────────

func RecordRequest()            { Global.RequestsTotal.Add(1) }
func RecordBlocked()            { Global.BlockedTotal.Add(1) }
func RecordSanitized()          { Global.SanitizedTotal.Add(1) }
func RecordRateLimited()        { Global.RateLimitedTotal.Add(1) }
func RecordObfuscated()         { Global.ObfuscatedTotal.Add(1) }

func RecordSTI(confidence string) {
	switch confidence {
	case "HIGH":   Global.STIHighTotal.Add(1)
	case "MEDIUM": Global.STIMediumTotal.Add(1)
	case "LOW":    Global.STILowTotal.Add(1)
	}
}

func RecordNLI(confidence string) {
	switch confidence {
	case "HIGH":   Global.NLIHighTotal.Add(1)
	case "MEDIUM": Global.NLIMediumTotal.Add(1)
	case "LOW":    Global.NLILowTotal.Add(1)
	}
}

// ── Prometheus text format ─────────────────────────────────────────────────────

// Handler returns an http.HandlerFunc that serves metrics in Prometheus
// text exposition format (Content-Type: text/plain; version=0.0.4).
func Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		writeMetrics(w)
	}
}

func writeMetrics(w io.Writer) {
	c := Global

	// llm_mon_requests_total
	writeCounter(w,
		"llm_mon_requests_total",
		"Total HTTP requests processed by the proxy",
		c.RequestsTotal.Load())

	// llm_mon_sti_alerts_total
	writeHelp(w, "llm_mon_sti_alerts_total",
		"counter", "STI-001 alerts fired by confidence level")
	writeLabel(w, "llm_mon_sti_alerts_total", "confidence", "HIGH",   c.STIHighTotal.Load())
	writeLabel(w, "llm_mon_sti_alerts_total", "confidence", "MEDIUM", c.STIMediumTotal.Load())
	writeLabel(w, "llm_mon_sti_alerts_total", "confidence", "LOW",    c.STILowTotal.Load())

	// llm_mon_nli_alerts_total
	writeHelp(w, "llm_mon_nli_alerts_total",
		"counter", "NLI-001 alerts fired by confidence level")
	writeLabel(w, "llm_mon_nli_alerts_total", "confidence", "HIGH",   c.NLIHighTotal.Load())
	writeLabel(w, "llm_mon_nli_alerts_total", "confidence", "MEDIUM", c.NLIMediumTotal.Load())
	writeLabel(w, "llm_mon_nli_alerts_total", "confidence", "LOW",    c.NLILowTotal.Load())

	// llm_mon_blocked_total
	writeCounter(w,
		"llm_mon_blocked_total",
		"Requests blocked by the proxy (HIGH confidence + BLOCK_MODE)",
		c.BlockedTotal.Load())

	// llm_mon_sanitized_total
	writeCounter(w,
		"llm_mon_sanitized_total",
		"Requests sanitized and forwarded (SANITIZE_MODE)",
		c.SanitizedTotal.Load())

	// llm_mon_rate_limited_total
	writeCounter(w,
		"llm_mon_rate_limited_total",
		"Requests rejected by the per-IP rate limiter",
		c.RateLimitedTotal.Load())

	// llm_mon_obfuscated_total
	writeCounter(w,
		"llm_mon_obfuscated_total",
		"Detections where obfuscation bypass was used (zero-width, homoglyphs, …)",
		c.ObfuscatedTotal.Load())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func writeCounter(w io.Writer, name, help string, value int64) {
	writeHelp(w, name, "counter", help)
	fmt.Fprintf(w, "%s %d\n\n", name, value)
}

func writeHelp(w io.Writer, name, typ, help string) {
	fmt.Fprintf(w, "# HELP %s %s\n", name, help)
	fmt.Fprintf(w, "# TYPE %s %s\n", name, typ)
}

func writeLabel(w io.Writer, name, labelKey, labelVal string, value int64) {
	fmt.Fprintf(w, "%s{%s=%q} %d\n", name, labelKey, labelVal, value)
}
