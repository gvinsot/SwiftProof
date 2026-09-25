// Package report decodes the SwiftProof confidence report (schema v1) and
// turns it into the view the web UI renders.
//
// The hub never re-derives conclusions: severities, statuses and counts are
// read from the report the CLI produced. It only regroups them into a single
// severity-ranked alert list, and attaches to every alert the modifications it
// concerns, so that the UI can show them without a second request.
package report

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Severity levels, ordered. The UI filter is a slider over these values.
const (
	SeverityLow      = "low"
	SeverityMedium   = "medium"
	SeverityHigh     = "high"
	SeverityCritical = "critical"
)

// Levels lists severities from least to most severe.
var Levels = []string{SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical}

// Rank orders a severity; unknown values sort as low, as the CLI does.
func Rank(severity string) int {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case SeverityCritical:
		return 3
	case SeverityHigh:
		return 2
	case SeverityMedium:
		return 1
	default:
		return 0
	}
}

// Normalize maps any recorded severity onto a known level.
func Normalize(severity string) string {
	return Levels[Rank(severity)]
}

// maxDiffLines bounds the diff carried by one view. A generated pull request
// can rewrite a whole tree; the browser still has to stay responsive.
const maxDiffLines = 40000

// Alert kinds, most conclusive first.
const (
	KindIssue  = "issue"  // a hypothesis, possibly reproduced by a differential test
	KindCheck  = "check"  // a configured check that did not pass
	KindSignal = "signal" // a deterministic risk signal from the linter
	KindFocus  = "focus"  // a prioritized review target
)

// DiffLine mirrors one line of a hunk.
type DiffLine struct {
	Kind    string `json:"kind"`
	OldLine int    `json:"old_line,omitempty"`
	NewLine int    `json:"new_line,omitempty"`
	Content string `json:"content"`
}

// Hunk mirrors one diff hunk.
type Hunk struct {
	OldStart int        `json:"old_start"`
	OldLines int        `json:"old_lines"`
	NewStart int        `json:"new_start"`
	NewLines int        `json:"new_lines"`
	Lines    []DiffLine `json:"lines"`
}

// ChangedFile mirrors one changed file of the analyzed range.
type ChangedFile struct {
	Path      string `json:"path"`
	OldPath   string `json:"old_path,omitempty"`
	Status    string `json:"status"`
	Binary    bool   `json:"binary"`
	Additions int    `json:"additions"`
	Deletions int    `json:"deletions"`
	Hunks     []Hunk `json:"hunks"`
}

// Change mirrors the analyzed range.
type Change struct {
	BaseRef    string        `json:"base_ref"`
	HeadRef    string        `json:"head_ref"`
	BaseCommit string        `json:"base_commit"`
	HeadCommit string        `json:"head_commit"`
	Files      []ChangedFile `json:"files"`
	Additions  int           `json:"additions"`
	Deletions  int           `json:"deletions"`
}

// Signal mirrors a linter signal.
type Signal struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	Path     string `json:"path"`
	Line     int    `json:"line"`
	EndLine  int    `json:"end_line,omitempty"`
	Side     string `json:"side,omitempty"`
	Symbol   string `json:"symbol,omitempty"`
	Severity string `json:"severity"`
	Summary  string `json:"summary"`
	Evidence string `json:"evidence"`
}

// Check mirrors one executed check.
type Check struct {
	ID         string   `json:"id"`
	Kind       string   `json:"kind"`
	Status     string   `json:"status"`
	Command    []string `json:"command,omitempty"`
	ExitCode   int      `json:"exit_code"`
	DurationMS int64    `json:"duration_ms"`
	Output     string   `json:"output"`
	Truncated  bool     `json:"truncated"`
}

// Evidence mirrors a recorded observation or differential test.
type Evidence struct {
	ID          string   `json:"id"`
	Kind        string   `json:"kind"`
	Description string   `json:"description"`
	Path        string   `json:"path,omitempty"`
	Output      string   `json:"output,omitempty"`
	CheckID     string   `json:"check_id,omitempty"`
	BaseCheckID string   `json:"base_check_id,omitempty"`
	Status      string   `json:"status"`
	Runner      string   `json:"runner,omitempty"`
	TestNames   []string `json:"test_names"`
}

// Hypothesis mirrors an investigated issue and the status the CLI derived.
type Hypothesis struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Severity    string   `json:"severity"`
	Status      string   `json:"status"`
	Rationale   string   `json:"rationale"`
	EvidenceIDs []string `json:"evidence_ids"`
	Path        string   `json:"path,omitempty"`
	Line        int      `json:"line,omitempty"`
}

// ReviewTarget mirrors one prioritized range of the review plan.
type ReviewTarget struct {
	Path      string   `json:"path"`
	StartLine int      `json:"start_line"`
	EndLine   int      `json:"end_line"`
	Side      string   `json:"side"`
	Severity  string   `json:"severity"`
	Reasons   []string `json:"reasons"`
	SignalIDs []string `json:"signal_ids"`
}

// ReviewSurface mirrors the prioritization counters.
type ReviewSurface struct {
	ChangedLines int    `json:"changed_lines"`
	FocusedLines int    `json:"focused_lines"`
	Note         string `json:"note"`
}

// Coverage mirrors changed-line execution, never expressed as a percentage.
type Coverage struct {
	Status           string `json:"status"`
	Reason           string `json:"reason,omitempty"`
	AddedLines       int    `json:"added_lines"`
	ExecutedLines    int    `json:"executed_lines"`
	NotExecutedLines int    `json:"not_executed_lines"`
	NoBlockLines     int    `json:"no_block_lines"`
	NotMeasuredLines int    `json:"not_measured_lines"`
	RemovedLines     int    `json:"removed_lines"`
	Note             string `json:"note"`
}

// Report is the subset of the v1 confidence report the hub consumes. Unknown
// fields are ignored on purpose: a newer CLI must not break the UI.
type Report struct {
	Version          int            `json:"version"`
	ToolVersion      string         `json:"tool_version"`
	GeneratedAt      time.Time      `json:"generated_at"`
	Intent           string         `json:"intent,omitempty"`
	Change           Change         `json:"change"`
	Signals          []Signal       `json:"linter"`
	Checks           []Check        `json:"checks"`
	Hypotheses       []Hypothesis   `json:"hypotheses"`
	Evidence         []Evidence     `json:"evidence"`
	ReproducedIssues []Hypothesis   `json:"reproduced_issues"`
	Unverified       []string       `json:"unverified"`
	ReviewTargets    []ReviewTarget `json:"review_targets"`
	ReviewSurface    ReviewSurface  `json:"review_surface"`
	Coverage         Coverage       `json:"coverage"`
	ExitCode         int            `json:"exit_code"`
}

// Decode parses a confidence report. Size is bounded by the caller.
func Decode(data []byte) (*Report, error) {
	var r Report
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("confidence report: %w", err)
	}
	if r.Version != 1 {
		return nil, fmt.Errorf("unsupported confidence report version %d", r.Version)
	}
	return &r, nil
}

// EvidenceRef is the trace shown under a reproduced or dismissed issue.
type EvidenceRef struct {
	ID          string   `json:"id"`
	Kind        string   `json:"kind"`
	Status      string   `json:"status"`
	Description string   `json:"description"`
	Runner      string   `json:"runner,omitempty"`
	TestNames   []string `json:"test_names,omitempty"`
	Output      string   `json:"output,omitempty"`
}

// Alert is one entry of the severity-filtered list. Path/Line/EndLine point at
// the modifications it concerns; the UI resolves them against Files.
type Alert struct {
	ID       string        `json:"id"`
	Kind     string        `json:"kind"`
	Severity string        `json:"severity"`
	Title    string        `json:"title"`
	Detail   string        `json:"detail,omitempty"`
	Path     string        `json:"path,omitempty"`
	Line     int           `json:"line,omitempty"`
	EndLine  int           `json:"end_line,omitempty"`
	Side     string        `json:"side,omitempty"`
	Status   string        `json:"status,omitempty"`
	Reasons  []string      `json:"reasons,omitempty"`
	Evidence []EvidenceRef `json:"evidence,omitempty"`
}

// Counts holds how many alerts each severity carries.
type Counts struct {
	Low      int `json:"low"`
	Medium   int `json:"medium"`
	High     int `json:"high"`
	Critical int `json:"critical"`
	Total    int `json:"total"`
}

// Add records one alert of the given severity.
func (c *Counts) Add(severity string) {
	switch Normalize(severity) {
	case SeverityCritical:
		c.Critical++
	case SeverityHigh:
		c.High++
	case SeverityMedium:
		c.Medium++
	default:
		c.Low++
	}
	c.Total++
}

// AtLeast returns how many alerts reach the given severity.
func (c Counts) AtLeast(severity string) int {
	switch Rank(severity) {
	case 3:
		return c.Critical
	case 2:
		return c.Critical + c.High
	case 1:
		return c.Critical + c.High + c.Medium
	default:
		return c.Total
	}
}

// Verdicts derived from the CLI exit code, never from a model's claim.
const (
	VerdictBlocked = "blocked" // a high or critical issue was reproduced
	VerdictReview  = "review"  // something needs a human decision
	VerdictClear   = "clear"   // nothing reproduced and nothing left unverified
	VerdictFailed  = "failed"  // the analysis itself could not complete
)

// Verdict maps a CLI exit code. Clear is never a correctness claim: it only
// means this run reproduced no blocker and left no check unresolved.
func Verdict(exitCode int) string {
	switch exitCode {
	case 0:
		return VerdictClear
	case 1:
		return VerdictBlocked
	case 2:
		return VerdictReview
	default:
		return VerdictFailed
	}
}

// Summary is the compact repository-level result kept next to each commit.
type Summary struct {
	Verdict       string `json:"verdict"`
	ExitCode      int    `json:"exit_code"`
	Counts        Counts `json:"counts"`
	Reproduced    int    `json:"reproduced"`
	Unverified    int    `json:"unverified"`
	ChangedFiles  int    `json:"changed_files"`
	Additions     int    `json:"additions"`
	Deletions     int    `json:"deletions"`
	ChangedLines  int    `json:"changed_lines"`
	FocusedLines  int    `json:"focused_lines"`
	ChecksPassed  int    `json:"checks_passed"`
	ChecksFailed  int    `json:"checks_failed"`
	ToolVersion   string `json:"tool_version"`
	CoverageState string `json:"coverage_state"`
}

// View is what the browser renders: a summary, the ranked alerts and the
// modifications each alert points into.
type View struct {
	Summary        Summary       `json:"summary"`
	Change         Change        `json:"change"`
	Alerts         []Alert       `json:"alerts"`
	Files          []ChangedFile `json:"files"`
	Coverage       Coverage      `json:"coverage"`
	ReviewSurface  ReviewSurface `json:"review_surface"`
	Unverified     []string      `json:"unverified"`
	Checks         []Check       `json:"checks"`
	Intent         string        `json:"intent,omitempty"`
	DiffTruncated  bool          `json:"diff_truncated"`
	GeneratedAt    time.Time     `json:"generated_at"`
	ToolVersion    string        `json:"tool_version"`
	SeverityLevels []string      `json:"severity_levels"`
}

// Summarize computes the compact result without building the full view.
func (r *Report) Summarize() Summary {
	s := Summary{
		Verdict:       Verdict(r.ExitCode),
		ExitCode:      r.ExitCode,
		Reproduced:    len(r.ReproducedIssues),
		Unverified:    len(r.Unverified),
		ChangedFiles:  len(r.Change.Files),
		Additions:     r.Change.Additions,
		Deletions:     r.Change.Deletions,
		ChangedLines:  r.ReviewSurface.ChangedLines,
		FocusedLines:  r.ReviewSurface.FocusedLines,
		ToolVersion:   r.ToolVersion,
		CoverageState: r.Coverage.Status,
	}
	for _, c := range r.Checks {
		if c.Status == "PASS" && c.ExitCode == 0 {
			s.ChecksPassed++
		} else {
			s.ChecksFailed++
		}
	}
	for _, a := range r.Alerts() {
		s.Counts.Add(a.Severity)
	}
	return s
}

// Alerts flattens issues, failed checks, signals and review targets into one
// ranked list. Ordering is by severity, then by conclusiveness, then by
// location, so the first screen always holds what matters most.
func (r *Report) Alerts() []Alert {
	evidence := make(map[string]Evidence, len(r.Evidence))
	for _, e := range r.Evidence {
		evidence[e.ID] = e
	}
	alerts := make([]Alert, 0, len(r.Hypotheses)+len(r.Signals)+len(r.ReviewTargets))
	for _, h := range r.Hypotheses {
		a := Alert{
			ID:       "issue:" + h.ID,
			Kind:     KindIssue,
			Severity: Normalize(h.Severity),
			Title:    h.Title,
			Detail:   h.Rationale,
			Path:     h.Path,
			Line:     h.Line,
			EndLine:  h.Line,
			Side:     "new",
			Status:   h.Status,
		}
		for _, id := range h.EvidenceIDs {
			e, ok := evidence[id]
			if !ok {
				continue
			}
			a.Evidence = append(a.Evidence, EvidenceRef{
				ID: e.ID, Kind: e.Kind, Status: e.Status, Description: e.Description,
				Runner: e.Runner, TestNames: e.TestNames, Output: e.Output,
			})
		}
		alerts = append(alerts, a)
	}
	for _, c := range r.Checks {
		if c.Status == "PASS" && c.ExitCode == 0 {
			continue
		}
		severity := SeverityHigh
		if c.Status == "SKIPPED" {
			severity = SeverityMedium
		}
		alerts = append(alerts, Alert{
			ID:       "check:" + c.ID,
			Kind:     KindCheck,
			Severity: severity,
			Title:    checkTitle(c),
			Detail:   c.Output,
			Status:   c.Status,
		})
	}
	for _, s := range r.Signals {
		end := s.EndLine
		if end < s.Line {
			end = s.Line
		}
		side := s.Side
		if side == "" {
			side = "new"
		}
		alerts = append(alerts, Alert{
			ID:       "signal:" + s.ID,
			Kind:     KindSignal,
			Severity: Normalize(s.Severity),
			Title:    signalTitle(s),
			Detail:   s.Evidence,
			Path:     s.Path,
			Line:     s.Line,
			EndLine:  end,
			Side:     side,
			Status:   "OBSERVED",
			Reasons:  []string{s.Kind},
		})
	}
	for i, t := range r.ReviewTargets {
		side := t.Side
		if side == "" {
			side = "new"
		}
		alerts = append(alerts, Alert{
			ID:       fmt.Sprintf("focus:%d", i),
			Kind:     KindFocus,
			Severity: Normalize(t.Severity),
			Title:    fmt.Sprintf("%s:%d-%d", t.Path, t.StartLine, t.EndLine),
			Path:     t.Path,
			Line:     t.StartLine,
			EndLine:  t.EndLine,
			Side:     side,
			Reasons:  t.Reasons,
		})
	}
	sort.SliceStable(alerts, func(i, j int) bool {
		a, b := alerts[i], alerts[j]
		if ra, rb := Rank(a.Severity), Rank(b.Severity); ra != rb {
			return ra > rb
		}
		if ka, kb := kindRank(a), kindRank(b); ka != kb {
			return ka < kb
		}
		if sa, sb := statusRank(a.Status), statusRank(b.Status); sa != sb {
			return sa < sb
		}
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		return a.Line < b.Line
	})
	return alerts
}

func checkTitle(c Check) string {
	name := c.Kind
	if name == "" {
		name = c.ID
	}
	return fmt.Sprintf("Check %s: %s (exit %d)", name, strings.ToLower(c.Status), c.ExitCode)
}

func signalTitle(s Signal) string {
	if s.Symbol != "" {
		return fmt.Sprintf("%s — %s", s.Summary, s.Symbol)
	}
	return s.Summary
}

func kindRank(a Alert) int {
	switch a.Kind {
	case KindIssue:
		return 0
	case KindCheck:
		return 1
	case KindSignal:
		return 2
	default:
		return 3
	}
}

// A reproduced issue outranks an unverified hypothesis of the same severity:
// one is evidence, the other is a question.
func statusRank(status string) int {
	switch strings.ToUpper(status) {
	case "REPRODUCED":
		return 0
	case "UNVERIFIED":
		return 1
	case "FAIL", "ERROR", "TIMEOUT":
		return 2
	case "NOT_REPRODUCED":
		return 4
	case "DISMISSED":
		return 5
	default:
		return 3
	}
}

// BuildView assembles everything the report page needs in one payload.
func (r *Report) BuildView() View {
	v := View{
		Summary:        r.Summarize(),
		Change:         Change{BaseRef: r.Change.BaseRef, HeadRef: r.Change.HeadRef, BaseCommit: r.Change.BaseCommit, HeadCommit: r.Change.HeadCommit, Additions: r.Change.Additions, Deletions: r.Change.Deletions},
		Alerts:         r.Alerts(),
		Coverage:       r.Coverage,
		ReviewSurface:  r.ReviewSurface,
		Unverified:     r.Unverified,
		Checks:         r.Checks,
		Intent:         r.Intent,
		GeneratedAt:    r.GeneratedAt,
		ToolVersion:    r.ToolVersion,
		SeverityLevels: Levels,
	}
	budget := maxDiffLines
	v.Files = make([]ChangedFile, 0, len(r.Change.Files))
	for _, f := range r.Change.Files {
		kept := ChangedFile{Path: f.Path, OldPath: f.OldPath, Status: f.Status, Binary: f.Binary, Additions: f.Additions, Deletions: f.Deletions}
		for _, h := range f.Hunks {
			if len(h.Lines) > budget {
				v.DiffTruncated = true
				break
			}
			budget -= len(h.Lines)
			kept.Hunks = append(kept.Hunks, h)
		}
		v.Files = append(v.Files, kept)
	}
	return v
}
