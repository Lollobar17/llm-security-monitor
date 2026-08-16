// Package sanitizer implements Layer 3: active request sanitization.
//
// Instead of blocking a request, the sanitizer removes or escapes detected
// STI tokens and NLI injection phrases before the request reaches the model.
// The proxy forwards the cleaned body and adds X-Sanitized audit headers.
//
// Modes:
//
//	ESCAPE  replace detections with a visible placeholder (default)
//	STRIP   remove detections entirely
package sanitizer

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Lollobar17/llm-security-monitor/internal/detector"
	"github.com/Lollobar17/llm-security-monitor/internal/nlp"
)

// Mode controls how detected content is handled.
type Mode string

const (
	ModeEscape Mode = "ESCAPE" // replace with a visible placeholder
	ModeStrip  Mode = "STRIP"  // remove entirely
)

// Config holds sanitizer settings.
type Config struct {
	Mode           Mode
	STIPlaceholder string
	NLIPlaceholder string
}

// Default returns production-safe defaults.
func Default() Config {
	return Config{
		Mode:           ModeEscape,
		STIPlaceholder: "[FILTERED:STI]",
		NLIPlaceholder: "[FILTERED:NLI]",
	}
}

// Report describes what was changed.
type Report struct {
	Applied         bool
	STIReplacements int
	NLIReplacements int
	ChangedMessages []int
	RemovedTokens   []string
	RemovedPatterns []string
}

// nliEntry holds one NLI replacement: a regex and a label.
type nliEntry struct {
	id    string
	regex interface{ ReplaceAllString(string, string) string }
}

// Sanitizer applies active remediation to Chat Completions request bodies.
type Sanitizer struct{ cfg Config }

// New creates a Sanitizer with the given config.
func New(cfg Config) *Sanitizer { return &Sanitizer{cfg: cfg} }

// ── Public API ─────────────────────────────────────────────────────────────────

// Sanitize modifies req, replacing all detected STI tokens and NLI phrases.
func (s *Sanitizer) Sanitize(
	req detector.Request,
	stiFindings []detector.Finding,
	nliFindings []nlp.NLIFinding,
) (detector.Request, Report) {
	report := Report{}
	if len(stiFindings) == 0 && len(nliFindings) == 0 {
		return req, report
	}

	// Build per-message STI token lists
	stiByMsg := map[int][]string{}
	for _, f := range stiFindings {
		stiByMsg[f.MessageIndex] = append(stiByMsg[f.MessageIndex], f.Token.Value)
		report.RemovedTokens = append(report.RemovedTokens, f.Token.Value)
	}

	// Build per-message NLI regex lists
	nliByMsg := map[int][]nliEntry{}
	for _, f := range nliFindings {
		nliByMsg[f.MessageIndex] = append(nliByMsg[f.MessageIndex], nliEntry{
			id:    f.Pattern.ID,
			regex: f.Pattern.Regex,
		})
		report.RemovedPatterns = append(report.RemovedPatterns, f.Pattern.ID)
	}

	// Collect affected indices
	affected := map[int]bool{}
	for idx := range stiByMsg { affected[idx] = true }
	for idx := range nliByMsg { affected[idx] = true }

	newMessages := make([]detector.Message, len(req.Messages))
	copy(newMessages, req.Messages)

	for idx := range affected {
		if idx >= len(newMessages) {
			continue
		}
		newContent, stiN, nliN := s.processContent(
			newMessages[idx].Content,
			stiByMsg[idx],
			nliByMsg[idx],
		)
		newMessages[idx].Content = newContent
		report.STIReplacements += stiN
		report.NLIReplacements += nliN
		report.ChangedMessages = append(report.ChangedMessages, idx)
	}

	req.Messages = newMessages
	report.Applied = report.STIReplacements+report.NLIReplacements > 0
	return req, report
}

// SanitizeBody takes raw JSON bytes and returns sanitized JSON bytes.
func (s *Sanitizer) SanitizeBody(
	body []byte,
	stiFindings []detector.Finding,
	nliFindings []nlp.NLIFinding,
) ([]byte, Report, error) {
	var req detector.Request
	if err := json.Unmarshal(body, &req); err != nil {
		return body, Report{}, fmt.Errorf("parse: %w", err)
	}
	sanitized, report := s.Sanitize(req, stiFindings, nliFindings)
	if !report.Applied {
		return body, report, nil
	}
	out, err := json.Marshal(sanitized)
	if err != nil {
		return body, report, fmt.Errorf("re-serialize: %w", err)
	}
	return out, report, nil
}

// ── Internal ───────────────────────────────────────────────────────────────────

// contentPart is a single item in a multi-part content array.
type contentPart struct {
	Type     string          `json:"type"`
	Text     string          `json:"text,omitempty"`
	ImageURL json.RawMessage `json:"image_url,omitempty"`
}

func (s *Sanitizer) processContent(
	raw json.RawMessage,
	stiTokens []string,
	nliEntries []nliEntry,
) (json.RawMessage, int, int) {
	// String content
	var str string
	if err := json.Unmarshal(raw, &str); err == nil {
		clean, stiN, nliN := s.applyReplacements(str, stiTokens, nliEntries)
		out, _ := json.Marshal(clean)
		return out, stiN, nliN
	}
	// Array of content parts
	var parts []contentPart
	if err := json.Unmarshal(raw, &parts); err == nil {
		totalSTI, totalNLI := 0, 0
		for i, p := range parts {
			if p.Type == "text" {
				clean, stiN, nliN := s.applyReplacements(p.Text, stiTokens, nliEntries)
				parts[i].Text = clean
				totalSTI += stiN
				totalNLI += nliN
			}
		}
		out, _ := json.Marshal(parts)
		return out, totalSTI, totalNLI
	}
	return raw, 0, 0
}

func (s *Sanitizer) applyReplacements(
	text string,
	stiTokens []string,
	entries []nliEntry,
) (string, int, int) {
	result, stiCount, nliCount := text, 0, 0

	for _, token := range stiTokens {
		before := result
		if s.cfg.Mode == ModeStrip {
			result = strings.ReplaceAll(result, token, "")
		} else {
			result = strings.ReplaceAll(result, token, s.cfg.STIPlaceholder)
		}
		if result != before {
			stiCount++
		}
	}

	for _, e := range entries {
		before := result
		if s.cfg.Mode == ModeStrip {
			result = e.regex.ReplaceAllString(result, "")
		} else {
			result = e.regex.ReplaceAllString(result, s.cfg.NLIPlaceholder)
		}
		if result != before {
			nliCount++
		}
	}

	return result, stiCount, nliCount
}
