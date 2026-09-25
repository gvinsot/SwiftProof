// Package redact holds SwiftProof's best-effort credential redaction and
// UTF-8-safe truncation. It is a leaf package: it imports only the standard
// library, so that every layer (including packages below harness) can redact
// what it keeps without an import cycle. harness keeps thin wrappers
// (harness.Redact and its truncation helper) around these functions.
package redact

import (
	"regexp"
	"strings"
	"unicode/utf8"
)

// Marker replaces every redacted credential literal.
const Marker = "[REDACTED]"

var rules = []*regexp.Regexp{
	regexp.MustCompile(`(?is)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)`),
	regexp.MustCompile(`(?i)(?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|secret|password|passwd|authorization)["']?\s*[=:]\s*["']?[^\s,"'}]+`),
	regexp.MustCompile(`(?i)Bearer\s+[A-Za-z0-9._~+/=-]+`),
	regexp.MustCompile(`(?:sk-[A-Za-z0-9_-]{8,}|gh[pousr]_[A-Za-z0-9_]{8,}|github_pat_[A-Za-z0-9_]{8,}|AKIA[A-Z0-9]{16})`),
	regexp.MustCompile(`eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`),
	regexp.MustCompile(`://[^\s/@:]+:[^\s/@]+@`),
}

// maxPasses bounds how often Redact re-applies the rules before it falls back
// to masking the whole text.
const maxPasses = 8

// Redact masks common credential formats before any tool output or report is
// emitted. Each match becomes Marker followed by as many newlines as the match
// contained, so line numbering is preserved. It is defense in depth, not a
// guarantee that no secret remains.
//
// Redact is idempotent: Redact(Redact(s)) == Redact(s). A replacement can
// complete a new match (in "://0:://0:0@@" the inner "://0:0@" is masked
// first, which turns the outer text into "://0:[REDACTED]@"), so the rules are
// re-applied until the text stops changing. Every pass that changes the text
// consumes rule literals that no marker contains, so a fixed point is always
// reached. When more than maxPasses changing passes would be needed (only
// adversarially nested input needs them), the whole text becomes one Marker
// followed by its newlines, which is itself a fixed point: over-masking is the
// fail-safe direction, and the cost stays linear in the input size.
//
// Callers that store structured output rely on this: a value that is a fixed
// point is never altered by a later Redact, for example by report sanitizing.
func Redact(s string) string {
	for i := 0; i <= maxPasses; i++ {
		next := apply(s)
		if next == s {
			return s
		}
		s = next
	}
	return Marker + strings.Repeat("\n", strings.Count(s, "\n"))
}

// apply is one pass of every rule, in order.
func apply(s string) string {
	for _, re := range rules {
		s = re.ReplaceAllStringFunc(s, func(match string) string {
			return Marker + strings.Repeat("\n", strings.Count(match, "\n"))
		})
	}
	return s
}

// IsFixedPoint reports whether Redact leaves s unchanged. It is equivalent to
// Redact(s) == s and costs a single pass.
func IsFixedPoint(s string) bool { return apply(s) == s }

// TruncateUTF8 returns s cut to at most limit bytes without splitting a UTF-8
// sequence. A string that already fits has its invalid UTF-8 sequences
// replaced with U+FFFD instead; a longer one is cut and then shortened until it
// is valid UTF-8. A negative limit is treated as 0.
func TruncateUTF8(s string, limit int) string {
	if limit < 0 {
		limit = 0
	}
	if len(s) <= limit {
		return strings.ToValidUTF8(s, "�")
	}
	s = s[:limit]
	for len(s) > 0 && !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}
