// LLM Security Monitor — STI-001 / NLI-001 Reverse Proxy
//
// Three detection layers + active sanitization + rate limiting + metrics:
//
//   Layer 1 : STI-001 Special Token Injection (token registry + obfuscation)
//   Layer 2 : NLI-001 Natural Language Injection (regex + leet + fuzzy)
//   Layer 3a: Active sanitizer (SANITIZE_MODE)
//   Extra   : Per-IP token bucket rate limiter (RATE_LIMIT_RPS)
//   Extra   : Prometheus metrics endpoint (/metrics)
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

// ── Config ─────────────────────────────────────────────────────────────────────

type config struct {
	upstreamURL    string
	port           string
	blockMode      bool
	sanitizeMode   bool
	checkAllRoles  bool
	siemWebhook    string
	rateLimitRPS   float64
	rateLimitBurst float64
	logLevel       slog.Level
}

func loadConfig() config {
	rps, _   := strconv.ParseFloat(env("RATE_LIMIT_RPS",   "20"), 64)
	burst, _ := strconv.ParseFloat(env("RATE_LIMIT_BURST", "50"), 64)

	c := config{
		upstreamURL:    env("UPSTREAM_URL",    "http://localhost:11434"),
		port:           env("PROXY_PORT",      "8080"),
		blockMode:      env("BLOCK_MODE",      "false") == "true",
		sanitizeMode:   env("SANITIZE_MODE",   "false") == "true",
		checkAllRoles:  env("CHECK_ALL_ROLES", "false") == "true",
		siemWebhook:    env("SIEM_WEBHOOK",    ""),
		rateLimitRPS:   rps,
		rateLimitBurst: burst,
		logLevel:       slog.LevelInfo,
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

// ── Combined scan result ───────────────────────────────────────────────────────

type scanResult struct {
	STI       *detector.Result
	NLI       *nlp.NLIResult
	Triggered bool
	IsHigh    bool
}

func isHighConfidence(sr scanResult) bool {
	stiHigh := sr.STI != nil && sr.STI.Confidence == detector.ConfidenceHigh
	nliHigh := sr.NLI != nil && sr.NLI.Confidence == "HIGH"
	return stiHigh || nliHigh
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

	mode := "alert-only"
	if cfg.sanitizeMode { mode = "sanitize" }
	if cfg.blockMode    { mode = "block" }

	slog.Info("LLM Security Monitor started",
		"addr",         ":"+cfg.port,
		"upstream",     cfg.upstreamURL,
		"mode",         mode,
		"rate_limit",   fmt.Sprintf("%.0f rps (burst %.0f)", cfg.rateLimitRPS, cfg.rateLimitBurst),
		"all_roles",    cfg.checkAllRoles,
	)

	mux := http.NewServeMux()

	// Detection endpoints — wrapped with rate limiter
	inspectH := limiter.Middleware(inspectHandler(stiDet, nliDet, san, rp, cfg))
	mux.Handle("/v1/chat/completions", inspectH)
	mux.Handle("/api/chat",            inspectH)

	// Observability
	mux.HandleFunc("/health",  healthHandler(cfg))
	mux.HandleFunc("/metrics", metrics.Handler())
	mux.HandleFunc("/stats",   statsHandler())

	// Transparent passthrough for everything else
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

		if scan.Triggered {
			emitAlerts(scan, cfg)

			if scan.IsHigh {
				if cfg.sanitizeMode {
					body = applySanitizer(w, san, body, scan)
				} else if cfg.blockMode {
					metrics.RecordBlocked()
					w.Header().Set("Content-Type", "application/json")
					w.Header().Set("X-Blocked-By", "LLM-Security-Monitor")
					w.WriteHeader(http.StatusForbidden)
					json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
						"error": map[string]any{
							"message": "Request blocked: injection detected.",
							"code":    "STI-001/NLI-001",
							"type":    "security_violation",
						},
					})
					return
				}
			}

			// Alert-only: informational headers
			if scan.STI != nil && scan.STI.Triggered {
				w.Header().Set("X-STI-Alert",      "true")
				w.Header().Set("X-STI-Confidence", string(scan.STI.Confidence))
			}
			if scan.NLI != nil && scan.NLI.Triggered {
				w.Header().Set("X-NLI-Alert",      "true")
				w.Header().Set("X-NLI-Confidence", scan.NLI.Confidence)
			}
		}

		r.Body          = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))
		rp.ServeHTTP(w, r)
	}
}

func applySanitizer(
	w   http.ResponseWriter,
	san *sanitizer.Sanitizer,
	body []byte,
	scan scanResult,
) []byte {
	var stiFindings []detector.Finding
	var nliFindings []nlp.NLIFinding
	if scan.STI != nil { stiFindings = scan.STI.Findings }
	if scan.NLI != nil { nliFindings = scan.NLI.Findings }

	cleanBody, report, err := san.SanitizeBody(body, stiFindings, nliFindings)
	if err != nil || !report.Applied {
		return body
	}

	metrics.RecordSanitized()
	w.Header().Set("X-Sanitized",     "true")
	w.Header().Set("X-Sanitized-STI", strconv.Itoa(report.STIReplacements))
	w.Header().Set("X-Sanitized-NLI", strconv.Itoa(report.NLIReplacements))

	slog.Info("request sanitized",
		"src", scan.STI.SourceIP,
		"sti", report.STIReplacements,
		"nli", report.NLIReplacements,
	)
	return cleanBody
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

	sr := scanResult{STI: stiResult, NLI: nliResult, Triggered: triggered}
	sr.IsHigh = isHighConfidence(sr)
	return sr
}

// toNLIMessages converts a Chat Completions request to the NLI message format.
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

// ── Alert emission ────────────────────────────────────────────────────────────

func emitAlerts(scan scanResult, cfg config) {
	if scan.STI != nil && scan.STI.Triggered {
		conf := string(scan.STI.Confidence)
		metrics.RecordSTI(conf)

		// Track obfuscation bypasses
		for _, f := range scan.STI.Findings {
			if len(f.ObfuscationTechniques) > 0 {
				metrics.RecordObfuscated()
				break
			}
		}

		slog.Warn("STI-001 FIRED",
			"src",        scan.STI.SourceIP,
			"model",      scan.STI.Model,
			"confidence", conf,
			"severity",   scan.STI.Confidence.Severity(),
			"findings",   len(scan.STI.Findings),
		)
		for _, f := range scan.STI.Findings {
			slog.Debug("sti-finding",
				"token",       f.Token.Value,
				"risk",        f.Token.Risk.String(),
				"obfuscated",  len(f.ObfuscationTechniques) > 0,
				"techniques",  f.ObfuscationTechniques,
			)
		}
	}

	if scan.NLI != nil && scan.NLI.Triggered {
		metrics.RecordNLI(scan.NLI.Confidence)
		slog.Warn("NLI-001 FIRED",
			"src",        scan.NLI.SourceIP,
			"model",      scan.NLI.Model,
			"confidence", scan.NLI.Confidence,
			"findings",   len(scan.NLI.Findings),
		)
		for _, f := range scan.NLI.Findings {
			slog.Debug("nli-finding",
				"pattern",  f.Pattern.ID,
				"category", string(f.Pattern.Category),
				"match",    f.MatchType,
			)
		}
	}

	if cfg.siemWebhook != "" {
		go postWebhook(cfg.siemWebhook, scan)
	}
}

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
		json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
			"status":    "ok",
			"service":   "llm-security-monitor",
			"rules":     []string{"STI-001", "NLI-001"},
			"upstream":  cfg.upstreamURL,
			"mode": func() string {
				if cfg.sanitizeMode { return "sanitize" }
				if cfg.blockMode    { return "block" }
				return "alert-only"
			}(),
			"timestamp": time.Now().UTC().Format(time.RFC3339),
		})
	}
}

func statsHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
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
