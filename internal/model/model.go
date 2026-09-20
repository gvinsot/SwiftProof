// Package model defines the versioned, provider-independent review evidence format.
package model

import "time"

type DiffLine struct {
	Kind    string `json:"kind"`
	OldLine int    `json:"old_line,omitempty"`
	NewLine int    `json:"new_line,omitempty"`
	Content string `json:"content"`
}
type Hunk struct {
	OldStart int        `json:"old_start"`
	OldLines int        `json:"old_lines"`
	NewStart int        `json:"new_start"`
	NewLines int        `json:"new_lines"`
	Lines    []DiffLine `json:"lines"`
}
type ChangedFile struct {
	Path      string `json:"path"`
	OldPath   string `json:"old_path,omitempty"`
	Status    string `json:"status"`
	Binary    bool   `json:"binary"`
	Additions int    `json:"additions"`
	Deletions int    `json:"deletions"`
	Hunks     []Hunk `json:"hunks"`
}
type Change struct {
	BaseRef    string        `json:"base_ref"`
	HeadRef    string        `json:"head_ref"`
	BaseCommit string        `json:"base_commit"`
	HeadCommit string        `json:"head_commit"`
	Files      []ChangedFile `json:"files"`
	Additions  int           `json:"additions"`
	Deletions  int           `json:"deletions"`
}
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
type ReviewTarget struct {
	Path      string   `json:"path"`
	StartLine int      `json:"start_line"`
	EndLine   int      `json:"end_line"`
	Side      string   `json:"side"`
	Severity  string   `json:"severity"`
	Reasons   []string `json:"reasons"`
	SignalIDs []string `json:"signal_ids"`
}

// CoverageFile records how the added lines of one changed file resolved
// against a recorded coverage profile.
type CoverageFile struct {
	Path             string `json:"path"`
	Status           string `json:"status"`
	AddedLines       int    `json:"added_lines"`
	ExecutedLines    int    `json:"executed_lines"`
	NotExecutedLines int    `json:"not_executed_lines"`
	NoBlockLines     int    `json:"no_block_lines"`
	NotMeasuredLines int    `json:"not_measured_lines"`
}

// Coverage records which added lines a recorded run executed. Executed means a
// line ran at least once; it is never a claim that behavior is asserted,
// correct or safe. Removed lines have no candidate-side coordinate and are
// reported beside the four states rather than inside them.
type Coverage struct {
	Status           string         `json:"status"`
	Reason           string         `json:"reason,omitempty"`
	CheckID          string         `json:"check_id,omitempty"`
	ProfileSHA256    string         `json:"profile_sha256,omitempty"`
	Command          []string       `json:"command,omitempty"`
	AddedLines       int            `json:"added_lines"`
	ExecutedLines    int            `json:"executed_lines"`
	NotExecutedLines int            `json:"not_executed_lines"`
	NoBlockLines     int            `json:"no_block_lines"`
	NotMeasuredLines int            `json:"not_measured_lines"`
	RemovedLines     int            `json:"removed_lines"`
	Files            []CoverageFile `json:"files"`
	Note             string         `json:"note"`
}
type Artifact struct {
	Path   string `json:"path"`
	Kind   string `json:"kind"`
	SHA256 string `json:"sha256,omitempty"`
}
type AuditEvent struct {
	Time       time.Time `json:"time"`
	Tool       string    `json:"tool"`
	Arguments  string    `json:"arguments"`
	Status     string    `json:"status"`
	DurationMS int64     `json:"duration_ms"`
}
type ReviewSurface struct {
	ChangedLines int    `json:"changed_lines"`
	FocusedLines int    `json:"focused_lines"`
	Note         string `json:"note"`
}
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
	Artifacts        []Artifact     `json:"artifacts"`
	Audit            []AuditEvent   `json:"audit"`
	ExitCode         int            `json:"exit_code"`
}
