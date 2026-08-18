package metrics

import (
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
)

type Collector struct {
	RequestsTotal    atomic.Int64
	STIHighTotal     atomic.Int64
	STIMediumTotal   atomic.Int64
	STILowTotal      atomic.Int64
	NLIHighTotal     atomic.Int64
	NLIMediumTotal   atomic.Int64
	NLILowTotal      atomic.Int64
	BlockedTotal     atomic.Int64
	SanitizedTotal   atomic.Int64
	RateLimitedTotal atomic.Int64
	ObfuscatedTotal  atomic.Int64
	STIShadowTotal   atomic.Int64
	NLIShadowTotal   atomic.Int64
}

var Global = &Collector{}

func RecordRequest()     { Global.RequestsTotal.Add(1) }
func RecordBlocked()     { Global.BlockedTotal.Add(1) }
func RecordSanitized()   { Global.SanitizedTotal.Add(1) }
func RecordRateLimited() { Global.RateLimitedTotal.Add(1) }
func RecordObfuscated()  { Global.ObfuscatedTotal.Add(1) }
func RecordSTIShadow()   { Global.STIShadowTotal.Add(1) }
func RecordNLIShadow()   { Global.NLIShadowTotal.Add(1) }

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

func Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		writeMetrics(w)
	}
}

func writeMetrics(w io.Writer) {
	c := Global

	writeCounter(w, "llm_mon_requests_total",
		"Total HTTP requests processed by the proxy",
		c.RequestsTotal.Load())

	writeHelp(w, "llm_mon_sti_alerts_total", "counter",
		"STI-001 alerts fired by confidence level")
	writeLabel(w, "llm_mon_sti_alerts_total", "confidence", "HIGH",   c.STIHighTotal.Load())
	writeLabel(w, "llm_mon_sti_alerts_total", "confidence", "MEDIUM", c.STIMediumTotal.Load())
	writeLabel(w, "llm_mon_sti_alerts_total", "confidence", "LOW",    c.STILowTotal.Load())

	writeHelp(w, "llm_mon_nli_alerts_total", "counter",
		"NLI-001 alerts fired by confidence level")
	writeLabel(w, "llm_mon_nli_alerts_total", "confidence", "HIGH",   c.NLIHighTotal.Load())
	writeLabel(w, "llm_mon_nli_alerts_total", "confidence", "MEDIUM", c.NLIMediumTotal.Load())
	writeLabel(w, "llm_mon_nli_alerts_total", "confidence", "LOW",    c.NLILowTotal.Load())

	writeCounter(w, "llm_mon_blocked_total",
		"Requests blocked by the proxy",
		c.BlockedTotal.Load())

	writeCounter(w, "llm_mon_sanitized_total",
		"Requests sanitized and forwarded",
		c.SanitizedTotal.Load())

	writeCounter(w, "llm_mon_rate_limited_total",
		"Requests rejected by the per-IP rate limiter",
		c.RateLimitedTotal.Load())

	writeCounter(w, "llm_mon_obfuscated_total",
		"Detections where obfuscation bypass was used",
		c.ObfuscatedTotal.Load())

	writeCounter(w, "llm_mon_sti_shadow_total",
		"STI-001 detections in shadow (log-only) mode — would have been blocked",
		c.STIShadowTotal.Load())

	writeCounter(w, "llm_mon_nli_shadow_total",
		"NLI-001 detections in shadow (log-only) mode — would have been blocked",
		c.NLIShadowTotal.Load())
}

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
