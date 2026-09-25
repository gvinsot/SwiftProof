package model

// Changed-baseline-test section statuses and per-test change classes.
const (
	BaseTestsNoCandidates     = "no_candidates"
	BaseTestsRan              = "ran"
	BaseTestsNotRun           = "not_run"
	BaseTestRemoved           = "removed"
	BaseTestModified          = "modified"
	BaseTestSharedCodeChanged = "shared_code_changed"
	BaseTestFileDeleted       = "file_deleted"
)

// BaseTestsNote is the fixed note of the base_tests section. F3 owns its final
// text; this neutral sentence makes no claim.
const BaseTestsNote = "See the documentation for what this section does and does not establish."

type BaseTest struct {
	Name             string `json:"name"`
	Path             string `json:"path"`
	Line             int    `json:"line"`
	EndLine          int    `json:"end_line"`
	CandidatePath    string `json:"candidate_path,omitempty"`
	CandidateLine    int    `json:"candidate_line,omitempty"`
	CandidateEndLine int    `json:"candidate_end_line,omitempty"`
	Change           string `json:"change"`
	Status           string `json:"status"` // FAILS_ON_CANDIDATE | PASSES_ON_CANDIDATE | UNVERIFIED
	EvidenceID       string `json:"evidence_id,omitempty"`
	Reason           string `json:"reason,omitempty"`
}

// BaseTests is the changed-baseline-test section. It is present exactly when
// review ran with --base-tests.
type BaseTests struct {
	Status string     `json:"status"`
	Reason string     `json:"reason,omitempty"`
	Tests  []BaseTest `json:"tests"`
	Note   string     `json:"note"`
}
