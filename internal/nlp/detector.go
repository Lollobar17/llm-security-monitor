package nlp

import (
	"fmt"
	"strings"
	"time"
	"unicode"
)

// ── Leet-speak normalizer ──────────────────────────────────────────────────────

// leetTable maps common leet substitutions to their ASCII equivalents.
// Applied before regex matching to catch "1gnor3 4ll pr3vi0us 1nstruct10ns".
var leetTable = map[rune]rune{
	'0': 'o',
	'1': 'i',
	'2': 'z',
	'3': 'e',
	'4': 'a',
	'5': 's',
	'6': 'g',
	'7': 't',
	'8': 'b',
	'9': 'g',
	'@': 'a',
	'$': 's',
	'!': 'i',
	'+': 't',
}

func normalizeLeet(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if ascii, ok := leetTable[r]; ok {
			b.WriteRune(ascii)
		} else {
			b.WriteRune(unicode.ToLower(r))
		}
	}
	return b.String()
}

// ── Levenshtein fuzzy matching ────────────────────────────────────────────────

// levenshtein computes the edit distance between two strings.
func levenshtein(a, b []rune) int {
	la, lb := len(a), len(b)
	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}

	prev := make([]int, lb+1)
	curr := make([]int, lb+1)
	for j := 0; j <= lb; j++ {
		prev[j] = j
	}
	for i := 1; i <= la; i++ {
		curr[0] = i
		for j := 1; j <= lb; j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			curr[j] = min3(curr[j-1]+1, prev[j]+1, prev[j-1]+cost)
		}
		prev, curr = curr, prev
	}
	return prev[lb]
}

func min3(a, b, c int) int {
	if a < b {
		if a < c {
			return a
		}
		return c
	}
	if b < c {
		return b
	}
	return c
}

// fuzzyMatch returns true if the input contains a substring whose
// Levenshtein distance from phrase is ≤ maxDist.
// Uses a sliding window of ±20% the phrase length for efficiency.
func fuzzyMatch(input string, phrase string, maxDist int) bool {
	phraseRunes := []rune(strings.ToLower(phrase))
	inputRunes := []rune(strings.ToLower(input))

	pl := len(phraseRunes)
	il := len(inputRunes)
	if pl == 0 || il == 0 {
		return false
	}

	// Window: phrase length ± 30% to allow insertions/deletions
	winMin := pl - pl/3
	winMax := pl + pl/3
	if winMin < 1 {
		winMin = 1
	}
	if winMax > il {
		winMax = il
	}

	for start := 0; start <= il-winMin; start++ {
		for wlen := winMin; wlen <= winMax && start+wlen <= il; wlen++ {
			window := inputRunes[start : start+wlen]
			if levenshtein(phraseRunes, window) <= maxDist {
				return true
			}
		}
	}
	return false
}

// ── Result types ──────────────────────────────────────────────────────────────

// NLIFinding represents a single NLP injection pattern match.
type NLIFinding struct {
	Pattern      Pattern
	MessageIndex int
	MessageRole  string
	FieldPath    string
	Context      string // snippet around the match
	MatchType    string // "REGEX", "LEET", "FUZZY"
}

func (f NLIFinding) String() string {
	return fmt.Sprintf("[%s] %s (%s) in %s via %s — %s",
		f.Pattern.Risk, f.Pattern.ID, f.Pattern.Category,
		f.FieldPath, f.MatchType, f.Pattern.Description)
}

// NLIResult is the output of NLI-001 analysis on one request.
type NLIResult struct {
	RuleID     string
	Triggered  bool
	Confidence string
	Findings   []NLIFinding
	SourceIP   string
	Model      string
	Timestamp  time.Time
}

func (r *NLIResult) Severity() string {
	switch r.Confidence {
	case "HIGH":
		return "CRITICAL"
	case "MEDIUM":
		return "HIGH"
	case "LOW":
		return "MEDIUM"
	default:
		return "INFO"
	}
}

func (r *NLIResult) ToMap() map[string]any {
	findings := make([]map[string]any, len(r.Findings))
	for i, f := range r.Findings {
		findings[i] = map[string]any{
			"pattern_id":  f.Pattern.ID,
			"category":    string(f.Pattern.Category),
			"risk":        f.Pattern.Risk.String(),
			"description": f.Pattern.Description,
			"role":        f.MessageRole,
			"field":       f.FieldPath,
			"context":     f.Context,
			"match_type":  f.MatchType,
		}
	}
	return map[string]any{
		"rule_id":    r.RuleID,
		"triggered":  r.Triggered,
		"severity":   r.Severity(),
		"confidence": r.Confidence,
		"source_ip":  r.SourceIP,
		"model":      r.Model,
		"timestamp":  r.Timestamp.UTC().Format(time.RFC3339),
		"attack_class": "Natural Language Injection (NLI)",
		"mitre": map[string]any{
			"tactic":    []string{"Initial Access", "ML Attack Staging"},
			"technique": []string{"T1190"},
			"atlas":     []string{"AML.T0051", "AML.T0054"},
		},
		"findings_count": len(r.Findings),
		"findings":       findings,
		"remediation": []string{
			"Add NLI pattern filtering at the application layer before forwarding to LLM",
			"Implement structured output validation — reject responses that contradict system role",
			"Use a separate privileged system prompt channel not exposed to user input",
			"Apply prompt hardening: explicitly tell the model to ignore attempts to change its role",
		},
	}
}

// ── Detector ──────────────────────────────────────────────────────────────────

// Detector runs NLI-001 pattern analysis on Chat Completions messages.
type Detector struct {
	// FuzzyThreshold: max Levenshtein distance allowed for HIGH-risk patterns.
	// Default: 3 (catches up to 3 character substitutions/insertions).
	FuzzyThreshold int
	enableFuzzy    bool
	enableLeet     bool
}

// New returns a Detector with default settings.
func New() *Detector {
	return &Detector{
		FuzzyThreshold: 3,
		enableFuzzy:    true,
		enableLeet:     true,
	}
}

// suspiciousRoles mirrors the STI detector: only scan user-controlled fields.
var suspiciousRoles = map[string]bool{
	"user":     true,
	"tool":     true,
	"function": true,
}

// minTextLen is the minimum rune length of a text segment before NLI analysis
// is attempted. Messages shorter than this cannot plausibly contain a credible
// injection phrase and would only generate fuzzy false positives.
const minTextLen = 20

// hasAnchor returns true if at least one anchor word from the pattern's
// phrase appears as a substring in the lowercased input text.
// This is the O(n) pre-filter that gates the O(n×m) Levenshtein call.
func hasAnchor(textLow string, anchors []string) bool {
	for _, a := range anchors {
		if strings.Contains(textLow, a) {
			return true
		}
	}
	return false
}

// Analyze runs NLI-001 on a messages array (same format as detector.Request.Messages).
// The caller passes pre-extracted (role, texts) pairs to avoid re-parsing JSON.
func (d *Detector) Analyze(messages []Message, sourceIP, model string) *NLIResult {
	result := &NLIResult{
		RuleID:    "NLI-001",
		SourceIP:  sourceIP,
		Model:     model,
		Timestamp: time.Now(),
	}

	type dedupKey struct {
		patternID string
		field     string
	}
	seen := map[dedupKey]bool{}

	for _, msg := range messages {
		if !suspiciousRoles[msg.Role] {
			continue
		}

		for _, seg := range msg.Segments {
			fieldPath := seg.Field
			text := seg.Text

			// Skip very short messages — too brief to be a credible injection
			// and generates false positives on fuzzy matching.
			if len([]rune(text)) < minTextLen {
				continue
			}

			leet     := normalizeLeet(text)
			textLow  := strings.ToLower(text)

			for _, pat := range Patterns {
				key := dedupKey{pat.ID, fieldPath}
				if seen[key] {
					continue
				}

				// ── Layer 1: regex on original text ───────────────────────────
				if pat.Regex.MatchString(text) {
					seen[key] = true
					result.Findings = append(result.Findings, NLIFinding{
						Pattern:     pat,
					MessageIndex: msg.Index,
						MessageRole: msg.Role,
						FieldPath:   fieldPath,
						Context:     extractContext(text, pat.Regex, 50),
						MatchType:   "REGEX",
					})
					continue
				}

				// ── Layer 2: regex on leet-normalized text ────────────────────
				if d.enableLeet && pat.Regex.MatchString(leet) {
					seen[key] = true
					result.Findings = append(result.Findings, NLIFinding{
						Pattern:     pat,
					MessageIndex: msg.Index,
						MessageRole: msg.Role,
						FieldPath:   fieldPath,
						Context:     text[:min(80, len(text))],
						MatchType:   "LEET",
					})
					continue
				}

				// ── Layer 3: fuzzy match (HIGH-risk patterns, long phrases only) ─
				// Gate 1: minimum phrase length (avoids FP on short tokens like "[DAN]")
				// Gate 2: anchor word pre-filter — at least one content word from
				//         the pattern phrase must appear in the text before we pay
				//         the O(n×m) cost of Levenshtein. On clean inputs this
				//         eliminates virtually all fuzzy calls.
				if d.enableFuzzy && pat.Risk == RiskHigh && len(pat.Phrase) >= 15 {
					// Anchor pre-filter
					if !hasAnchor(textLow, pat.Anchors) {
						continue
					}
					// Scale threshold: ≤ 10% of phrase length, min 2, max FuzzyThreshold
					thresh := len(pat.Phrase) * 10 / 100
					if thresh < 2 {
						thresh = 2
					}
					if thresh > d.FuzzyThreshold {
						thresh = d.FuzzyThreshold
					}
					if fuzzyMatch(text, pat.Phrase, thresh) {
						seen[key] = true
						result.Findings = append(result.Findings, NLIFinding{
							Pattern:      pat,
							MessageIndex: msg.Index,
							MessageRole:  msg.Role,
							FieldPath:    fieldPath,
							Context:      text[:min(80, len(text))],
							MatchType:    "FUZZY",
						})
					}
				}
			}
		}
	}

	result.Confidence = scoreFindings(result.Findings)
	result.Triggered = result.Confidence != "NONE"
	return result
}

// ── Message type (shared between nlp and caller) ──────────────────────────────

// Message is a simplified message representation for NLI analysis.
type Message struct {
	Index    int // position in the messages array
	Role     string
	Segments []Segment
}

// Segment holds one text block and its JSON field path.
type Segment struct {
	Field string
	Text  string
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func scoreFindings(findings []NLIFinding) string {
	if len(findings) == 0 {
		return "NONE"
	}
	highCount, medCount := 0, 0
	for _, f := range findings {
		switch f.Pattern.Risk {
		case RiskHigh:
			highCount++
		case RiskMedium:
			medCount++
		}
	}
	if highCount >= 1 || medCount >= 2 {
		return "HIGH"
	}
	if medCount >= 1 {
		return "MEDIUM"
	}
	return "LOW"
}

func extractContext(text string, rx interface{ FindStringIndex(string) []int }, pad int) string {
	loc := rx.FindStringIndex(text)
	if loc == nil {
		return ""
	}
	start := loc[0] - pad
	if start < 0 {
		start = 0
	}
	end := loc[1] + pad
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

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
