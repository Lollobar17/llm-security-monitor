// Package obfuscation provides multi-pass input normalization to detect
// special token injection attempts that use character-level obfuscation
// to bypass exact-string detectors.
//
// Normalization passes (applied in order):
//  1. Zero-width character stripping  (U+200B, U+200C, U+200D, U+FEFF, …)
//  2. HTML entity unescaping          (&lt; → <, &#124; → |, …)
//  3. URL / percent decoding          (%3C%7C → <|, …)
//  4. Homoglyph replacement           (＜｜ → <|, fullwidth / lookalikes)
//
// Each pass records whether it changed the string, so callers can report
// exactly which obfuscation technique was used in a finding.
package obfuscation

import (
	"html"
	"net/url"
	"strings"
)

// Technique names returned by Normalize.
const (
	TechZeroWidth  = "ZERO_WIDTH_CHARS"
	TechHTMLEntity = "HTML_ENTITIES"
	TechURLEncoded = "URL_ENCODING"
	TechHomoglyph  = "HOMOGLYPHS"
)

// Result holds the normalized string and which techniques were detected.
type Result struct {
	Original   string
	Normalized string
	Techniques []string // non-empty when obfuscation was detected
}

// WasObfuscated returns true if any normalization pass changed the input.
func (r Result) WasObfuscated() bool { return len(r.Techniques) > 0 }

// Normalizer applies all passes in sequence.
type Normalizer struct{}

// New returns a ready-to-use Normalizer.
func New() *Normalizer { return &Normalizer{} }

// Normalize runs all four passes on input and returns a Result.
func (n *Normalizer) Normalize(input string) Result {
	r := Result{Original: input}
	current := input

	// ── Pass 1: zero-width characters ─────────────────────────────────────────
	stripped := stripZeroWidth(current)
	if stripped != current {
		r.Techniques = append(r.Techniques, TechZeroWidth)
		current = stripped
	}

	// ── Pass 2: HTML entity unescaping ────────────────────────────────────────
	unescaped := html.UnescapeString(current)
	if unescaped != current {
		r.Techniques = append(r.Techniques, TechHTMLEntity)
		current = unescaped
	}

	// ── Pass 3: URL / percent decoding ────────────────────────────────────────
	// PathUnescape handles %XX sequences without touching '+' → space.
	if urlDecoded, err := url.PathUnescape(current); err == nil && urlDecoded != current {
		r.Techniques = append(r.Techniques, TechURLEncoded)
		current = urlDecoded
	}

	// ── Pass 4: homoglyph replacement ─────────────────────────────────────────
	homoglyphed := replaceHomoglyphs(current)
	if homoglyphed != current {
		r.Techniques = append(r.Techniques, TechHomoglyph)
		current = homoglyphed
	}

	r.Normalized = current
	return r
}

// ── Pass 1: zero-width character table ────────────────────────────────────────

// zeroWidthChars lists Unicode code points that are invisible and can be
// inserted inside token strings to break exact-match detection.
var zeroWidthChars = []string{
	"\u200B", // ZERO WIDTH SPACE
	"\u200C", // ZERO WIDTH NON-JOINER
	"\u200D", // ZERO WIDTH JOINER
	"\u200E", // LEFT-TO-RIGHT MARK
	"\u200F", // RIGHT-TO-LEFT MARK
	"\u202A", // LEFT-TO-RIGHT EMBEDDING
	"\u202B", // RIGHT-TO-LEFT EMBEDDING
	"\u202C", // POP DIRECTIONAL FORMATTING
	"\u202D", // LEFT-TO-RIGHT OVERRIDE
	"\u202E", // RIGHT-TO-LEFT OVERRIDE
	"\u2060", // WORD JOINER
	"\u2061", // FUNCTION APPLICATION
	"\u2062", // INVISIBLE TIMES
	"\u2063", // INVISIBLE SEPARATOR
	"\u2064", // INVISIBLE PLUS
	"\uFEFF", // ZERO WIDTH NO-BREAK SPACE (BOM)
	"\u00AD", // SOFT HYPHEN
	"\u034F", // COMBINING GRAPHEME JOINER
	"\u115F", // HANGUL CHOSEONG FILLER
	"\u1160", // HANGUL JUNGSEONG FILLER
	"\u3164", // HANGUL FILLER
	"\uFFA0", // HALFWIDTH HANGUL FILLER
}

func stripZeroWidth(s string) string {
	for _, zw := range zeroWidthChars {
		s = strings.ReplaceAll(s, zw, "")
	}
	return s
}

// ── Pass 4: homoglyph table ───────────────────────────────────────────────────
//
// Maps visually similar Unicode characters to their ASCII equivalents.
// Focused on characters that appear in LLM special tokens:
//   < > | [ ] ( ) / \ _ - * . @ # !
//
// Sources: Unicode Confusables (https://util.unicode.org/UnicodeJsps/confusables.jsp)

var homoglyphTable = map[rune]rune{

	// ── Less-than / angle open (<) ─────────────────────────────────────────────
	'\uFF1C': '<', // ＜ FULLWIDTH LESS-THAN SIGN
	'\u2039': '<', // ‹ SINGLE LEFT-POINTING ANGLE QUOTATION MARK
	'\u27E8': '<', // ⟨ MATHEMATICAL LEFT ANGLE BRACKET
	'\u2329': '<', // 〈 LEFT-POINTING ANGLE BRACKET
	'\u3008': '<', // 〈 LEFT ANGLE BRACKET (CJK)
	'\u276E': '<', // ❮ HEAVY LEFT-POINTING ANGLE QUOTATION MARK
	'\u00AB': '<', // « LEFT-POINTING DOUBLE ANGLE QUOTATION MARK

	// ── Greater-than / angle close (>) ────────────────────────────────────────
	'\uFF1E': '>', // ＞ FULLWIDTH GREATER-THAN SIGN
	'\u203A': '>', // › SINGLE RIGHT-POINTING ANGLE QUOTATION MARK
	'\u27E9': '>', // ⟩ MATHEMATICAL RIGHT ANGLE BRACKET
	'\u232A': '>', // 〉 RIGHT-POINTING ANGLE BRACKET
	'\u3009': '>', // 〉 RIGHT ANGLE BRACKET (CJK)
	'\u276F': '>', // ❯ HEAVY RIGHT-POINTING ANGLE QUOTATION MARK
	'\u00BB': '>', // » RIGHT-POINTING DOUBLE ANGLE QUOTATION MARK

	// ── Vertical bar / pipe (|) ───────────────────────────────────────────────
	'\uFF5C': '|', // ｜ FULLWIDTH VERTICAL LINE
	'\u2223': '|', // ∣ DIVIDES
	'\u2502': '|', // │ BOX DRAWINGS LIGHT VERTICAL
	'\u23D0': '|', // ⏐ VERTICAL LINE EXTENSION
	'\u01C0': '|', // ǀ LATIN LETTER DENTAL CLICK
	'\u0028': '|', // misleading in some fonts — skip, too risky for FP
	'\uFFE8': '|', // ￨ HALFWIDTH FORMS LIGHT VERTICAL

	// ── Left square bracket ([) ───────────────────────────────────────────────
	'\uFF3B': '[', // ［ FULLWIDTH LEFT SQUARE BRACKET
	'\u2768': '[', // ❨ MEDIUM LEFT PARENTHESIS ORNAMENT
	'\u27E6': '[', // ⟦ MATHEMATICAL LEFT WHITE SQUARE BRACKET

	// ── Right square bracket (]) ──────────────────────────────────────────────
	'\uFF3D': ']', // ］ FULLWIDTH RIGHT SQUARE BRACKET
	'\u2769': ']', // ❩ MEDIUM RIGHT PARENTHESIS ORNAMENT
	'\u27E7': ']', // ⟧ MATHEMATICAL RIGHT WHITE SQUARE BRACKET

	// ── Slash (/) ─────────────────────────────────────────────────────────────
	'\uFF0F': '/', // ／ FULLWIDTH SOLIDUS
	'\u2215': '/', // ∕ DIVISION SLASH
	'\u29F8': '/', // ⧸ BIG SOLIDUS

	// ── Underscore (_) ────────────────────────────────────────────────────────
	'\uFF3F': '_', // ＿ FULLWIDTH LOW LINE
	'\u2017': '_', // ‗ DOUBLE LOW LINE (close enough)

	// ── Hyphen-minus (-) ──────────────────────────────────────────────────────
	'\u2010': '-', // ‐ HYPHEN
	'\u2011': '-', // ‑ NON-BREAKING HYPHEN
	'\u2012': '-', // ‒ FIGURE DASH
	'\u2013': '-', // – EN DASH
	'\u2212': '-', // − MINUS SIGN
	'\uFF0D': '-', // － FULLWIDTH HYPHEN-MINUS

	// ── Colon (:) ─────────────────────────────────────────────────────────────
	'\uFF1A': ':', // ： FULLWIDTH COLON
	'\u02D0': ':', // ː MODIFIER LETTER TRIANGULAR COLON

	// ── Space variations → ASCII space ────────────────────────────────────────
	'\u00A0': ' ', // NO-BREAK SPACE
	'\u2000': ' ', // EN QUAD
	'\u2001': ' ', // EM QUAD
	'\u2002': ' ', // EN SPACE
	'\u2003': ' ', // EM SPACE
	'\u2004': ' ', // THREE-PER-EM SPACE
	'\u2005': ' ', // FOUR-PER-EM SPACE
	'\u2006': ' ', // SIX-PER-EM SPACE
	'\u2007': ' ', // FIGURE SPACE
	'\u2008': ' ', // PUNCTUATION SPACE
	'\u2009': ' ', // THIN SPACE
	'\u200A': ' ', // HAIR SPACE
	'\u202F': ' ', // NARROW NO-BREAK SPACE
	'\u205F': ' ', // MEDIUM MATHEMATICAL SPACE
	'\u3000': ' ', // IDEOGRAPHIC SPACE
}

func replaceHomoglyphs(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if ascii, ok := homoglyphTable[r]; ok {
			b.WriteRune(ascii)
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}
