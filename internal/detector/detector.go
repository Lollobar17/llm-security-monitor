// Package detector implements the STI-001 detection engine.
//
// It parses Chat Completions API payloads and scans user-controlled message
// content for special token strings that indicate a Special Token Injection
// attempt.
package detector

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Lollobar17/llm-security-monitor/internal/obfuscation"
	"github.com/Lollobar17/llm-security-monitor/internal/registry"
)

// Roles that are user-controlled and should be inspected.
var suspiciousRoles = map[string]bool{
	"user":     true,
	"tool":     true,
	"function": true,
}

// Confidence represents the certainty level of a detection.
type Confidence string

const (
	ConfidenceNone   Confidence = "NONE"
	ConfidenceLow    Confidence = "LOW"
	ConfidenceMedium Confidence = "MEDIUM"
	ConfidenceHigh   Confidence = "HIGH"
)

// Severity maps confidence to SIEM severity strings.
func (c Confidence) Severity() string {
	switch c {
	case ConfidenceHigh:
		return "CRITICAL"
	case ConfidenceMedium:
		return "HIGH"
	case ConfidenceLow:
		return "MEDIUM"
	default:
		return "INFO"
	}
}

// ── Request types ─────────────────────────────────────────────────────────────

// Request is a /v1/chat/completions request body.
type Request struct {
	Model     string          `json:"model"`
	Messages  []Message       `json:"messages"`
	Stream    bool            `json:"stream"`
	MaxTokens *int            `json:"max_tokens,omitempty"`
	Tools     json.RawMessage `json:"tools,omitempty"`
}

// Message is a single entry in the messages array.
// Content is RawMessage because it can be either a string or an array of parts.
type Message struct {
	Role    string          `json:"role"`
	Content json.RawMessage `json:"content"`
}

// ContentPart is one element of a multi-part content array.
type ContentPart struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
}

// texts returns all text segments from a message content field.
// Handles both string and []ContentPart forms.
func (m *Message) texts() []string {
	if len(m.Content) == 0 {
		return nil
	}

	// Try string first
	var s string
	if err := json.Unmarshal(m.Content, &s); err == nil {
		return []string{s}
	}

	// Try array of parts
	var parts []ContentPart
	if err := json.Unmarshal(m.Content, &parts); err == nil {
		var out []string
		for _, p := range parts {
			if p.Type == "text" && p.Text != "" {
				out = append(out, p.Text)
			}
		}
		return out
	}

	return nil
}

// ── Detection result types ────────────────────────────────────────────────────

// Finding is a single token match inside a message.
type Finding struct {
	Token                registry.Token
	MessageIndex         int
	MessageRole          string
	FieldPath            string   // e.g. "messages[2].content"
	Context              string   // text snippet around the match (from normalized text)
	ObfuscationTechniques []string // non-empty when bypass techniques were detected
}

func (f Finding) String() string {
	obs := ""
	if len(f.ObfuscationTechniques) > 0 {
		obs = fmt.Sprintf(" [OBFUSCATED: %s]", strings.Join(f.ObfuscationTechniques, ", "))
	}
	return fmt.Sprintf("[%s] %q in %s (role=%s)%s — %s",
		f.Token.Risk, f.Token.Value, f.FieldPath, f.MessageRole, obs, f.Token.Description)
}

// Result is the outcome of analyzing one Chat Completions request.
type Result struct {
	RuleID     string
	Triggered  bool
	Confidence Confidence
	Findings   []Finding
	SourceIP   string
	Model      string
	Timestamp  time.Time
}

// ToMap serialises the result to a map suitable for JSON encoding / SIEM ingestion.
func (r *Result) ToMap() map[string]any {
	findings := make([]map[string]any, len(r.Findings))
	for i, f := range r.Findings {
		findings[i] = map[string]any{
			"token":                  f.Token.Value,
			"name":                   f.Token.Name,
			"architecture":           f.Token.Architecture,
			"risk":                   f.Token.Risk.String(),
			"description":            f.Token.Description,
			"role":                   f.MessageRole,
			"field":                  f.FieldPath,
			"context":                f.Context,
			"obfuscation_techniques": f.ObfuscationTechniques,
			"was_obfuscated":         len(f.ObfuscationTechniques) > 0,
		}
	}

	attackTypes := r.attackTypes()

	return map[string]any{
		"rule_id":     r.RuleID,
		"triggered":   r.Triggered,
		"severity":    r.Confidence.Severity(),
		"confidence":  string(r.Confidence),
		"source_ip":   r.SourceIP,
		"model":       r.Model,
		"timestamp":   r.Timestamp.UTC().Format(time.RFC3339),
		"attack_class": "Special Token Injection (STI)",
		"attack_types": attackTypes,
		"mitre": map[string]any{
			"tactic":    []string{"Initial Access", "ML Attack Staging"},
			"technique": []string{"T1190"},
			"atlas":     "AML.T0051",
		},
		"findings_count": len(r.Findings),
		"findings":       findings,
		"remediation": []string{
			"Set split_special_tokens=True in HuggingFace tokenizer config",
			"Sanitize user input before apply_chat_template()",
			"Validate tool call invocations against a strict schema before execution",
			"Apply input length limits at the API gateway layer",
		},
	}
}

func (r *Result) attackTypes() []string {
	seen := map[string]bool{}
	for _, f := range r.Findings {
		v := strings.ToLower(f.Token.Value)
		switch {
		case strings.Contains(v, "tool_call") ||
			strings.Contains(v, "tool_response") ||
			strings.Contains(v, "function"):
			seen["Function Call Hijacking"] = true
		case strings.Contains(v, "system") ||
			strings.Contains(v, "sys>>") ||
			strings.Contains(v, "inst") ||
			strings.Contains(v, "override"):
			seen["Role Escalation / System Override"] = true
		case strings.Contains(v, "im_end") ||
			strings.Contains(v, "</s>") ||
			strings.Contains(v, "endoftext"):
			seen["Message Boundary Injection"] = true
		default:
			seen["Generic Token Injection"] = true
		}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	return out
}

// ── Detector ──────────────────────────────────────────────────────────────────

// Detector inspects Chat Completions requests for Special Token Injection.
type Detector struct {
	checkAllRoles bool
	roles         map[string]bool
	normalizer    *obfuscation.Normalizer
}

// Option configures the Detector.
type Option func(*Detector)

// WithAllRoles makes the detector also scan system and assistant messages.
// Useful when the system prompt is dynamically constructed from external data.
func WithAllRoles() Option {
	return func(d *Detector) {
		d.checkAllRoles = true
		d.roles = map[string]bool{
			"user":      true,
			"tool":      true,
			"function":  true,
			"system":    true,
			"assistant": true,
		}
	}
}

// New returns a Detector with default configuration (user/tool/function roles).
func New(opts ...Option) *Detector {
	d := &Detector{
		checkAllRoles: false,
		roles:         suspiciousRoles,
		normalizer:    obfuscation.New(),
	}
	for _, o := range opts {
		o(d)
	}
	return d
}

// Analyze inspects a parsed Chat Completions request and returns a Result.
func (d *Detector) Analyze(req Request, sourceIP string) *Result {
	result := &Result{
		RuleID:    "STI-001",
		SourceIP:  sourceIP,
		Model:     req.Model,
		Timestamp: time.Now(),
	}

	type dedupKey struct {
		token string
		field string
	}
	seen := map[dedupKey]bool{}

	for i, msg := range req.Messages {
		if !d.roles[msg.Role] {
			continue
		}

		for _, text := range msg.texts() {
			// Normalize first — catches obfuscated payloads
			normResult := d.normalizer.Normalize(text)
			normalized := normResult.Normalized
			lower := strings.ToLower(normalized)

			for _, tok := range registry.Registry {
				if !strings.Contains(lower, strings.ToLower(tok.Value)) {
					continue
				}

				fieldPath := fmt.Sprintf("messages[%d].content", i)
				key := dedupKey{tok.Value, fieldPath}
				if seen[key] {
					continue
				}
				seen[key] = true

				result.Findings = append(result.Findings, Finding{
					Token:                 tok,
					MessageIndex:          i,
					MessageRole:           msg.Role,
					FieldPath:             fieldPath,
					Context:               snippet(normalized, tok.Value, 40),
					ObfuscationTechniques: normResult.Techniques,
				})
			}
		}
	}

	result.Confidence = score(result.Findings)
	result.Triggered = result.Confidence != ConfidenceNone
	return result
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// snippet returns a context window around the first occurrence of token in text.
func snippet(text, token string, pad int) string {
	idx := strings.Index(strings.ToLower(text), strings.ToLower(token))
	if idx < 0 {
		return ""
	}
	start := idx - pad
	if start < 0 {
		start = 0
	}
	end := idx + len(token) + pad
	if end > len(text) {
		end = len(text)
	}
	prefix, suffix := "", ""
	if start > 0 {
		prefix = "…"
	}
	if end < len(text) {
		suffix = "…"
	}
	return prefix + text[start:end] + suffix
}

// score derives the confidence level from a set of findings.
func score(findings []Finding) Confidence {
	if len(findings) == 0 {
		return ConfidenceNone
	}
	for _, f := range findings {
		if f.Token.Risk == registry.RiskHigh {
			return ConfidenceHigh
		}
	}
	for _, f := range findings {
		if f.Token.Risk == registry.RiskMedium {
			return ConfidenceMedium
		}
	}
	return ConfidenceLow
}
