// LLM Security Monitor — STI-001 / NLI-001 Reverse Proxy
//
// Three detection layers + active sanitization + rate limiting + metrics
// + granular shadow mode (per-rule block/sanitize/log):
//
//   STI_MODE = block | sanitize | log   (default: log)
//   NLI_MODE = block | sanitize | log   (default: log)
//   NLI_CONFIDENCE_THRESHOLD = HIGH | MEDIUM | LOW (default: HIGH)
//
//   Shadow mode example (block STI, observe NLI first):
//     STI_MODE=block NLI_MODE=log ./llm-security-monitor
//
//   Backward compat:
//     BLOCK_MODE=true    → STI_MODE=block  NLI_MODE=block
//     SANITIZE_MODE=true → STI_MODE=sanitize NLI_MODE=sanitize
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Lollobar17/llm-security-monitor/internal/detector"
	"github.com/Lollobar17/llm-security-monitor/internal/metrics"
	"github.com/Lollobar17/llm-security-monitor/internal/nlp"
	"github.com/Lollobar17/llm-security-monitor/internal/ratelimit"
	"github.com/Lollobar17/llm-security-monitor/internal/sanitizer"
)

// ── Detection mode ─────────────────────────────────────────────────────────────

type DetectionMode string

const (
	ModeBlock    DetectionMode = "block"    // return 403
	ModeSanitize DetectionMode = "sanitize" // clean and forward
	ModeLog      DetectionMode = "log"      // shadow: log only, never block
)

func parseMode(s, fallback string) DetectionMode {
	switch strings.ToLower(s) {
	case "block":
		return ModeBlock
	case "sanitize":
		return ModeSanitize
	case "log":
		return ModeLog
	default:
		return DetectionMode(fallback)
	}
}

// confidenceRank maps confidence strings to a numeric rank for threshold comparison.
func confidenceRank(c string) int {
	switch c {
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	case "LOW":
		return 1
	default:
		return 0
	}
}

// meetsThreshold returns true if confidence >= threshold.
func meetsThreshold(confidence, threshold string) bool {
	return confidenceRank(confidence) >= confidenceRank(threshold)
}

// ── Config ─────────────────────────────────────────────────────────────────────

type config struct {
	upstreamURL             string
	port                    string
	stiMode                 DetectionMode
	nliMode                 DetectionMode
	nliConfidenceThreshold  string // HIGH | MEDIUM | LOW
	checkAllRoles           bool
	siemWebhook             string
	rateLimitRPS            float64
	rateLimitBurst          float64
	logLevel                slog.Level
}

func loadConfig() config {
	rps, _   := strconv.ParseFloat(env("RATE_LIMIT_RPS",   "20"), 64)
	burst, _ := strconv.ParseFloat(env("RATE_LIMIT_BURST", "50"), 64)

	// Resolve STI_MODE / NLI_MODE with backward compat for BLOCK_MODE / SANITIZE_MODE
	stiModeRaw := env("STI_MODE", "")
	nliModeRaw := env("NLI_MODE", "")

	blockMode    := env("BLOCK_MODE",    "false") == "true"
	sanitizeMode := env("SANITIZE_MODE", "false") == "true"

	if stiModeRaw == "" {
		if blockMode {
			stiModeRaw = "block"
		} else if sanitizeMode {
			stiModeRaw = "sanitize"
		} else {
			stiModeRaw = "log"
		}
	}
	if nliModeRaw == "" {
		if blockMode {
			nliModeRaw = "block"
		} else if sanitizeMode {
			nliModeRaw = "sanitize"
		} else {
			nliModeRaw = "log"
		}
	}

	c := config{
		upstreamURL:            env("UPSTREAM_URL",              "http://localhost:11434"),
		port:                   env("PROXY_PORT",                "8080"),
		stiMode:                parseMode(stiModeRaw, "log"),
		nliMode:                parseMode(nliModeRaw, "log"),
		nliConfidenceThreshold: strings.ToUpper(env("NLI_CONFIDENCE_THRESHOLD", "HIGH")),
		checkAllRoles:          env("CHECK_ALL_ROLES", "false") == "true",
		siemWebhook:            env("SIEM_WEBHOOK", ""),
		rateLimitRPS:           rps,
		rateLimitBurst:         burst,
		logLevel:               slog.LevelInfo,
	}
	if env("LOG_LEVEL", "INFO") == "DEBUG" {
		c.logLevel = slog.LevelDebug
	}
	return c
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// ── Scan result ────────────────────────────────────────────────────────────────

type scanResult struct {
	STI       *detector.Result
	NLI       *nlp.NLIResult
	Triggered bool
}

// ── Main ──────────────────────────────────────────────────────────────────────

func main() {
	cfg := loadConfig()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: cfg.logLevel}))
	slog.SetDefault(logger)

	upstream, err := url.Parse(cfg.upstreamURL)
	if err != nil {
		slog.Error("invalid upstream URL", "url", cfg.upstreamURL, "err", err)
		os.Exit(1)
	}

	rp := httputil.NewSingleHostReverseProxy(upstream)
	rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		slog.Error("upstream error", "err", err)
		jsonError(w, http.StatusBadGateway, "upstream unreachable")
	}

	opts := []detector.Option{}
	if cfg.checkAllRoles {
		opts = append(opts, detector.WithAllRoles())
	}

	stiDet  := detector.New(opts...)
	nliDet  := nlp.New()
	san     := sanitizer.New(sanitizer.Default())
	limiter := ratelimit.New(cfg.rateLimitRPS, cfg.rateLimitBurst)
	defer limiter.Stop()

	slog.Info("LLM Security Monitor started",
		"addr",                   ":"+cfg.port,
		"upstream",               cfg.upstreamURL,
		"sti_mode",               string(cfg.stiMode),
		"nli_mode",               string(cfg.nliMode),
		"nli_confidence_threshold", cfg.nliConfidenceThreshold,
		"rate_limit",             fmt.Sprintf("%.0f rps (burst %.0f)", cfg.rateLimitRPS, cfg.rateLimitBurst),
	)

	mux := http.NewServeMux()
	inspectH := limiter.Middleware(inspectHandler(stiDet, nliDet, san, rp, cfg))
	mux.Handle("/v1/chat/completions", inspectH)
	mux.Handle("/api/chat",            inspectH)
	mux.HandleFunc("/health",  healthHandler(cfg))
	mux.HandleFunc("/metrics", metrics.Handler())
	mux.HandleFunc("/stats",   statsHandler())
	mux.Handle("/", rp)

	srv := &http.Server{
		Addr:         ":" + cfg.port,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 120 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	if err := srv.ListenAndServe(); err != nil {
		slog.Error("server stopped", "err", err)
		os.Exit(1)
	}
}

// ── Inspect handler ────────────────────────────────────────────────────────────

func inspectHandler(
	stiDet *detector.Detector,
	nliDet *nlp.Detector,
	san    *sanitizer.Sanitizer,
	rp     *httputil.ReverseProxy,
	cfg    config,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		metrics.RecordRequest()

		if r.Method != http.MethodPost {
			rp.ServeHTTP(w, r)
			return
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, 10<<20))
		_ = r.Body.Close()
		if err != nil {
			jsonError(w, http.StatusBadRequest, "failed to read body")
			return
		}

		var req detector.Request
		if err := json.Unmarshal(body, &req); err != nil {
			r.Body = io.NopCloser(bytes.NewReader(body))
			rp.ServeHTTP(w, r)
			return
		}

		srcIP := clientIP(r)
		scan  := runDetectors(stiDet, nliDet, req, srcIP)

		// Apply STI mode
		if scan.STI != nil && scan.STI.Triggered {
			blocked, newBody := applySTIMode(w, scan.STI, cfg, san, body)
			if blocked {
				return
			}
			if newBody != nil {
				body = newBody
			}
		}

		// Apply NLI mode (only if meets confidence threshold)
		if scan.NLI != nil && scan.NLI.Triggered &&
			meetsThreshold(scan.NLI.Confidence, cfg.nliConfidenceThreshold) {
			blocked, newBody := applyNLIMode(w, scan.NLI, scan.STI, cfg, san, body)
			if blocked {
				return
			}
			if newBody != nil {
				body = newBody
			}
		}

		// Emit webhook if anything triggered
		if scan.Triggered && cfg.siemWebhook != "" {
			go postWebhook(cfg.siemWebhook, scan)
		}

		r.Body          = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))
		rp.ServeHTTP(w, r)
	}
}

// applySTIMode handles the STI result according to the configured mode.
// Returns (blocked bool, sanitizedBody []byte).
func applySTIMode(
	w      http.ResponseWriter,
	result *detector.Result,
	cfg    config,
	san    *sanitizer.Sanitizer,
	body   []byte,
) (bool, []byte) {
	conf := string(result.Confidence)
	metrics.RecordSTI(conf)

	for _, f := range result.Findings {
		if len(f.ObfuscationTechniques) > 0 {
			metrics.RecordObfuscated()
			break
		}
	}

	slog.Warn("STI-001 FIRED",
		"src",        result.SourceIP,
		"model",      result.Model,
		"confidence", conf,
		"severity",   result.Confidence.Severity(),
		"findings",   len(result.Findings),
		"mode",       string(cfg.stiMode),
	)

	switch cfg.stiMode {
	case ModeBlock:
		metrics.RecordBlocked()
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Blocked-By", "STI-001")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": map[string]any{
				"message": "Request blocked: Special Token Injection detected.",
				"code":    "STI-001",
				"type":    "security_violation",
			},
		})
		return true, nil

	case ModeSanitize:
		cleanBody, report, err := san.SanitizeBody(body, result.Findings, nil)
		if err == nil && report.Applied {
			metrics.RecordSanitized()
			w.Header().Set("X-STI-Alert",      "true")
			w.Header().Set("X-STI-Confidence", conf)
			w.Header().Set("X-Sanitized",      "true")
			w.Header().Set("X-Sanitized-STI",  strconv.Itoa(report.STIReplacements))
			return false, cleanBody
		}

	case ModeLog:
		// Shadow mode: log but do not block or sanitize
		slog.Warn("STI-001 SHADOW",
			"src",         result.SourceIP,
			"confidence",  conf,
			"findings",    len(result.Findings),
			"would_block", true,
		)
		metrics.RecordSTIShadow()
		w.Header().Set("X-STI-Alert",      "true")
		w.Header().Set("X-STI-Confidence", conf)
		w.Header().Set("X-STI-Shadow",     "true")
	}

	return false, nil
}

// applyNLIMode handles the NLI result according to the configured mode.
func applyNLIMode(
	w         http.ResponseWriter,
	result    *nlp.NLIResult,
	stiResult *detector.Result,
	cfg       config,
	san       *sanitizer.Sanitizer,
	body      []byte,
) (bool, []byte) {
	conf := result.Confidence
	metrics.RecordNLI(conf)

	slog.Warn("NLI-001 FIRED",
		"src",        result.SourceIP,
		"model",      result.Model,
		"confidence", conf,
		"findings",   len(result.Findings),
		"mode",       string(cfg.nliMode),
		"threshold",  cfg.nliConfidenceThreshold,
	)

	switch cfg.nliMode {
	case ModeBlock:
		metrics.RecordBlocked()
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Blocked-By", "NLI-001")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": map[string]any{
				"message": "Request blocked: Natural Language Injection detected.",
				"code":    "NLI-001",
				"type":    "security_violation",
			},
		})
		return true, nil

	case ModeSanitize:
		var stiFindings []detector.Finding
		if stiResult != nil {
			stiFindings = stiResult.Findings
		}
		cleanBody, report, err := san.SanitizeBody(body, stiFindings, result.Findings)
		if err == nil && report.Applied {
			metrics.RecordSanitized()
			w.Header().Set("X-NLI-Alert",      "true")
			w.Header().Set("X-NLI-Confidence", conf)
			w.Header().Set("X-Sanitized",      "true")
			w.Header().Set("X-Sanitized-NLI",  strconv.Itoa(report.NLIReplacements))
			return false, cleanBody
		}

	case ModeLog:
		// Shadow mode: log only
		slog.Warn("NLI-001 SHADOW",
			"src",         result.SourceIP,
			"confidence",  conf,
			"findings",    len(result.Findings),
			"would_block", true,
		)
		metrics.RecordNLIShadow()
		w.Header().Set("X-NLI-Alert",      "true")
		w.Header().Set("X-NLI-Confidence", conf)
		w.Header().Set("X-NLI-Shadow",     "true")
	}

	return false, nil
}

// ── Parallel detection ────────────────────────────────────────────────────────

func runDetectors(
	stiDet *detector.Detector,
	nliDet *nlp.Detector,
	req    detector.Request,
	srcIP  string,
) scanResult {
	var (
		stiResult *detector.Result
		nliResult *nlp.NLIResult
		wg        sync.WaitGroup
	)
	wg.Add(2)
	go func() { defer wg.Done(); stiResult = stiDet.Analyze(req, srcIP) }()
	go func() { defer wg.Done(); nliResult = nliDet.Analyze(toNLIMessages(req), srcIP, req.Model) }()
	wg.Wait()

	triggered := (stiResult != nil && stiResult.Triggered) ||
		(nliResult != nil && nliResult.Triggered)

	return scanResult{STI: stiResult, NLI: nliResult, Triggered: triggered}
}

func toNLIMessages(req detector.Request) []nlp.Message {
	msgs := make([]nlp.Message, 0, len(req.Messages))
	for i, m := range req.Messages {
		msgs = append(msgs, nlp.Message{
			Index:    i,
			Role:     m.Role,
			Segments: extractSegments(m, i),
		})
	}
	return msgs
}

func extractSegments(m detector.Message, idx int) []nlp.Segment {
	field := fmt.Sprintf("messages[%d].content", idx)
	var s string
	if err := json.Unmarshal(m.Content, &s); err == nil {
		return []nlp.Segment{{Field: field, Text: s}}
	}
	var parts []struct {
		Type string `json:"type"`
		Text string `json:"text,omitempty"`
	}
	if err := json.Unmarshal(m.Content, &parts); err == nil {
		segs := make([]nlp.Segment, 0, len(parts))
		for j, p := range parts {
			if p.Type == "text" && p.Text != "" {
				segs = append(segs, nlp.Segment{
					Field: fmt.Sprintf("messages[%d].content[%d].text", idx, j),
					Text:  p.Text,
				})
			}
		}
		return segs
	}
	return nil
}

// ── Webhook ────────────────────────────────────────────────────────────────────

func postWebhook(webhookURL string, scan scanResult) {
	payload := map[string]any{}
	if scan.STI != nil && scan.STI.Triggered { payload["sti"] = scan.STI.ToMap() }
	if scan.NLI != nil && scan.NLI.Triggered { payload["nli"] = scan.NLI.ToMap() }
	data, err := json.Marshal(payload)
	if err != nil { return }
	resp, err := http.Post(webhookURL, "application/json", bytes.NewReader(data)) //nolint:noctx
	if err != nil {
		slog.Error("webhook failed", "err", err)
		return
	}
	resp.Body.Close()
}

// ── Utility handlers ──────────────────────────────────────────────────────────

func healthHandler(cfg config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":                    "ok",
			"service":                   "llm-security-monitor",
			"rules":                     []string{"STI-001", "NLI-001"},
			"upstream":                  cfg.upstreamURL,
			"sti_mode":                  string(cfg.stiMode),
			"nli_mode":                  string(cfg.nliMode),
			"nli_confidence_threshold":  cfg.nliConfidenceThreshold,
			"timestamp":                 time.Now().UTC().Format(time.RFC3339),
		})
	}
}

func statsHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"rules": map[string]string{
				"STI-001": "Special Token Injection",
				"NLI-001": "Natural Language Injection",
			},
			"metrics_endpoint": "/metrics",
		})
	}
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return strings.SplitN(xff, ",", 2)[0]
	}
	if r.RemoteAddr == "" { return "unknown" }
	if idx := strings.LastIndex(r.RemoteAddr, ":"); idx > 0 {
		return r.RemoteAddr[:idx]
	}
	return r.RemoteAddr
}

func jsonError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	fmt.Fprintf(w, `{"error":%q}`, msg)
}
