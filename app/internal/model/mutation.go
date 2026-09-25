package model

// Mutation section statuses, file statuses and mutant statuses.
const (
	MutationNotRun       = "not_run"
	MutationNoCandidates = "no_candidates"
	MutationRan          = "ran"
	MutationIncomplete   = "incomplete"
	MutationFileEligible = "eligible"
	MutationFileSkipped  = "skipped"
	MutantKilled         = "KILLED"
	MutantSurvived       = "SURVIVED"
	MutantInvalid        = "INVALID"
	MutantTimeout        = "TIMEOUT"
	MutantInconclusive   = "INCONCLUSIVE"
	MutantNotRun         = "NOT_RUN"
)

// MutationNote is the fixed note of the mutation section. F4 owns its final
// text; this neutral sentence makes no claim.
const MutationNote = "See the documentation for what this section does and does not establish."

type MutationLimits struct {
	MaxMutants        int `json:"max_mutants"`
	TimeoutSeconds    int `json:"timeout_seconds"`
	MaxRuntimeSeconds int `json:"max_runtime_seconds"`
}
type MutationFile struct {
	Path         string `json:"path"`
	Status       string `json:"status"`
	Reason       string `json:"reason,omitempty"`
	AddedLines   int    `json:"added_lines"`
	MutatedLines int    `json:"mutated_lines"`
}
type Mutant struct {
	ID             string   `json:"id"` // mutant-N
	Path           string   `json:"path"`
	Line           int      `json:"line"`
	Package        string   `json:"package"`
	Operator       string   `json:"operator"`
	Original       string   `json:"original"` // display, ≤256 bytes
	Mutated        string   `json:"mutated"`  // display, ≤256 bytes
	Status         string   `json:"status"`
	CheckID        string   `json:"check_id,omitempty"`
	ControlCheckID string   `json:"control_check_id,omitempty"`
	PatchSHA256    string   `json:"patch_sha256,omitempty"` // sha256 of the retained mutant_patch artifact
	TestsRun       int      `json:"tests_run,omitempty"`
	FailedTests    []string `json:"failed_tests,omitempty"`
	Reason         string   `json:"reason,omitempty"`
}

// Mutation is the mutation section. It is present exactly when the policy has
// mutation in review mode, whatever --checks says.
type Mutation struct {
	Status       string         `json:"status"`
	Reason       string         `json:"reason,omitempty"`
	Command      []string       `json:"command"`
	Limits       MutationLimits `json:"limits"`
	Files        []MutationFile `json:"files"`
	Mutants      []Mutant       `json:"mutants"`
	Generated    int            `json:"generated"`
	Dropped      int            `json:"dropped"` // candidates not run because of max_mutants
	Killed       int            `json:"killed"`
	Survived     int            `json:"survived"`
	Invalid      int            `json:"invalid"`
	TimedOut     int            `json:"timed_out"`
	Inconclusive int            `json:"inconclusive"`
	NotRun       int            `json:"not_run"`
	Checks       []Check        `json:"checks"` // mutation ledger: mutation-check-N
	Note         string         `json:"note"`
}
