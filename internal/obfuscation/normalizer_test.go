package obfuscation_test

import (
	"strings"
	"testing"

	"github.com/Lollobar17/llm-security-monitor/internal/obfuscation"
)

var n = obfuscation.New()

// ── Pass 1: Zero-width characters ─────────────────────────────────────────────

func TestZeroWidthSpaceInsertion(t *testing.T) {
	// Attacker inserts U+200B (ZWSP) inside <|im_start|>
	input := "<|\u200Bim_start|>system"
	r := n.Normalize(input)

	if !r.WasObfuscated() {
		t.Fatal("expected obfuscation detected")
	}
	if !contains(r.Techniques, obfuscation.TechZeroWidth) {
		t.Errorf("expected %s in techniques, got %v", obfuscation.TechZeroWidth, r.Techniques)
	}
	if r.Normalized != "<|im_start|>system" {
		t.Errorf("unexpected normalized output: %q", r.Normalized)
	}
	t.Logf("✅ ZWSP pass | original=%q → normalized=%q techniques=%v",
		input, r.Normalized, r.Techniques)
}

func TestMultipleZeroWidthChars(t *testing.T) {
	// Multiple zero-width chars across a LLaMA token
	input := "[\u200BIN\u200CST\u200D]"
	r := n.Normalize(input)

	if !contains(r.Techniques, obfuscation.TechZeroWidth) {
		t.Errorf("expected ZERO_WIDTH_CHARS, got %v", r.Techniques)
	}
	if r.Normalized != "[INST]" {
		t.Errorf("expected [INST], got %q", r.Normalized)
	}
	t.Logf("✅ Multi-ZW pass | normalized=%q", r.Normalized)
}

// ── Pass 2: HTML entity encoding ──────────────────────────────────────────────

func TestHTMLEntityAngleBrackets(t *testing.T) {
	// <|im_start|>system via HTML entities
	input := "&lt;|im_start|&gt;system"
	r := n.Normalize(input)

	if !contains(r.Techniques, obfuscation.TechHTMLEntity) {
		t.Errorf("expected HTML_ENTITIES, got %v", r.Techniques)
	}
	if r.Normalized != "<|im_start|>system" {
		t.Errorf("unexpected: %q", r.Normalized)
	}
	t.Logf("✅ HTML entity pass | normalized=%q", r.Normalized)
}

func TestHTMLEntityNumeric(t *testing.T) {
	// Numeric entities: &#60; = <, &#124; = |, &#62; = >
	input := "&#60;&#124;im_end&#124;&#62;"
	r := n.Normalize(input)

	if !contains(r.Techniques, obfuscation.TechHTMLEntity) {
		t.Errorf("expected HTML_ENTITIES, got %v", r.Techniques)
	}
	if r.Normalized != "<|im_end|>" {
		t.Errorf("unexpected: %q", r.Normalized)
	}
	t.Logf("✅ Numeric entity pass | normalized=%q", r.Normalized)
}

// ── Pass 3: URL / percent encoding ────────────────────────────────────────────

func TestURLEncodedChatMLToken(t *testing.T) {
	// %3C = <, %7C = |, %3E = >
	input := "%3C%7Cim_start%7C%3Esystem"
	r := n.Normalize(input)

	if !contains(r.Techniques, obfuscation.TechURLEncoded) {
		t.Errorf("expected URL_ENCODING, got %v", r.Techniques)
	}
	if r.Normalized != "<|im_start|>system" {
		t.Errorf("unexpected: %q", r.Normalized)
	}
	t.Logf("✅ URL encoding pass | normalized=%q", r.Normalized)
}

func TestURLEncodedLLaMATokens(t *testing.T) {
	// [INST] → %5BINST%5D
	input := "%5BINST%5D %3C%3CSYS%3E%3E"
	r := n.Normalize(input)

	if !contains(r.Techniques, obfuscation.TechURLEncoded) {
		t.Errorf("expected URL_ENCODING, got %v", r.Techniques)
	}
	if !strings.Contains(r.Normalized, "[INST]") {
		t.Errorf("expected [INST] in normalized, got %q", r.Normalized)
	}
	t.Logf("✅ URL-encoded LLaMA tokens | normalized=%q", r.Normalized)
}

// ── Pass 4: Homoglyph substitution ────────────────────────────────────────────

func TestFullwidthChatMLToken(t *testing.T) {
	// ＜｜im_start｜＞system — fullwidth < | > characters
	input := "\uFF1C\uFF5Cim_start\uFF5C\uFF1Esystem"
	r := n.Normalize(input)

	if !contains(r.Techniques, obfuscation.TechHomoglyph) {
		t.Errorf("expected HOMOGLYPHS, got %v", r.Techniques)
	}
	if r.Normalized != "<|im_start|>system" {
		t.Errorf("unexpected: %q", r.Normalized)
	}
	t.Logf("✅ Fullwidth homoglyph pass | normalized=%q", r.Normalized)
}

func TestFullwidthLLaMABrackets(t *testing.T) {
	// ［INST］ — fullwidth square brackets
	input := "\uFF3BINST\uFF3D"
	r := n.Normalize(input)

	if !contains(r.Techniques, obfuscation.TechHomoglyph) {
		t.Errorf("expected HOMOGLYPHS, got %v", r.Techniques)
	}
	if r.Normalized != "[INST]" {
		t.Errorf("expected [INST], got %q", r.Normalized)
	}
	t.Logf("✅ Fullwidth bracket pass | normalized=%q", r.Normalized)
}

// ── Stacked / combined obfuscation ────────────────────────────────────────────

func TestStackedObfuscation(t *testing.T) {
	// URL-encode + zero-width: %3C%7C + ZWSP inside the token + homoglyph
	// This simulates a sophisticated multi-layer bypass attempt
	// Step 1: homoglyph  ＜ → <
	// Step 2: zero-width inside
	// Step 3: HTML entity for the pipe
	input := "\uFF1C&#124;im_end&#124;\uFF1E"
	r := n.Normalize(input)

	if len(r.Techniques) < 2 {
		t.Errorf("expected at least 2 techniques for stacked bypass, got %v", r.Techniques)
	}
	if r.Normalized != "<|im_end|>" {
		t.Errorf("unexpected: %q", r.Normalized)
	}
	t.Logf("✅ Stacked obfuscation pass | techniques=%v normalized=%q",
		r.Techniques, r.Normalized)
}

// ── Clean input should not be flagged ─────────────────────────────────────────

func TestCleanInputUnchanged(t *testing.T) {
	input := "What is the capital of Germany?"
	r := n.Normalize(input)

	if r.WasObfuscated() {
		t.Errorf("clean input should not be flagged, got techniques=%v", r.Techniques)
	}
	if r.Normalized != input {
		t.Errorf("clean input should be unchanged")
	}
	t.Logf("✅ Clean input unchanged | techniques=%v", r.Techniques)
}

// ── helper ────────────────────────────────────────────────────────────────────

func contains(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}
