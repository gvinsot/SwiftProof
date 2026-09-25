package server

import (
	"fmt"
	"html"
	"net/http"
	"strings"

	"github.com/gvinsot/SwiftProof/hub/internal/report"
	"github.com/gvinsot/SwiftProof/hub/internal/store"
)

// handleBadge renders the latest verdict of a monitored repository as an SVG,
// for a README. It is addressed by the unguessable webhook routing key, so a
// private repository is not exposed by name, and it reports what the last run
// recorded — never an approval.
func (s *Server) handleBadge(w http.ResponseWriter, r *http.Request) {
	key := strings.TrimSuffix(r.PathValue("hook"), ".svg")
	label, value, color := "swiftproof", "unknown", "#9aa6b5"
	if repo, ok := s.hookRepo(key); ok {
		value, color = badgeState(repo)
	}
	w.Header().Set("Content-Type", "image/svg+xml; charset=utf-8")
	// A badge must never be cached across a new report.
	w.Header().Set("Cache-Control", "no-cache, max-age=0")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, badgeSVG(label, value, color))
}

func badgeState(repo *store.Repo) (string, string) {
	if repo.Latest == nil {
		return "no report", "#9aa6b5"
	}
	switch {
	case repo.Latest.Status == store.StatusQueued, repo.Latest.Status == store.StatusRunning:
		return "running", "#0f7b6c"
	case repo.Latest.Status == store.StatusFailed:
		return "failed", "#9aa6b5"
	}
	switch repo.Latest.Summary.Verdict {
	case report.VerdictBlocked:
		return "reproduced issue", "#c0392b"
	case report.VerdictReview:
		return fmt.Sprintf("%d to review", repo.Latest.Summary.Counts.Total), "#d68910"
	default:
		return "no blocker", "#0f7b6c"
	}
}

// badgeSVG renders a shields-style badge without any external dependency.
func badgeSVG(label, value, color string) string {
	// 6.5 px per character approximates the advance width of the 11 px
	// DejaVu/Verdana stack browsers fall back to, plus padding.
	labelWidth := len(label)*7 + 20
	valueWidth := len(value)*7 + 20
	total := labelWidth + valueWidth
	return fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="20" role="img" aria-label="%s: %s">
<title>%s: %s</title>
<linearGradient id="s" x2="0" y2="100%%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient>
<clipPath id="r"><rect width="%d" height="20" rx="3" fill="#fff"/></clipPath>
<g clip-path="url(#r)">
<rect width="%d" height="20" fill="#3c4551"/>
<rect x="%d" width="%d" height="20" fill="%s"/>
<rect width="%d" height="20" fill="url(#s)"/>
</g>
<g fill="#fff" text-anchor="middle" font-family="Verdana,DejaVu Sans,Geneva,sans-serif" font-size="11">
<text x="%d" y="14">%s</text>
<text x="%d" y="14">%s</text>
</g>
</svg>`,
		total, html.EscapeString(label), html.EscapeString(value),
		html.EscapeString(label), html.EscapeString(value),
		total, labelWidth, labelWidth, valueWidth, html.EscapeString(color), total,
		labelWidth/2, html.EscapeString(label),
		labelWidth+valueWidth/2, html.EscapeString(value))
}
