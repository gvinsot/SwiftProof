package model

// Fuzz section statuses, function outcomes and the seed scheme.
const (
	FuzzRan          = "ran"
	FuzzNoCandidates = "no_candidates"
	FuzzNotRun       = "not_run"
	FuzzDisabled     = "disabled"
	FuzzDiverged     = "diverged"
	FuzzNotDiverged  = "not_diverged"
	FuzzInconclusive = "inconclusive"
	FuzzSeedScheme   = "swiftproof-fuzz/v1"
)

// FuzzNote is the fixed note of the fuzz section. F2 owns its final text; this
// neutral sentence makes no claim.
const FuzzNote = "See the documentation for what this section does and does not establish."

type FuzzLimits struct {
	MaxFunctions      int `json:"max_functions"`
	MaxPackages       int `json:"max_packages"`
	MaxInputs         int `json:"max_inputs"`
	CallTimeoutMS     int `json:"call_timeout_ms"`
	MaxRuntimeSeconds int `json:"max_runtime_seconds"`
}
type FuzzChecks struct {
	Base             string `json:"base"`
	Candidate        string `json:"candidate"`
	BaseConfirm      string `json:"base_confirm,omitempty"`
	CandidateConfirm string `json:"candidate_confirm,omitempty"`
}
type FuzzCounterexample struct {
	Index     int    `json:"index"`
	Input     string `json:"input"`
	Base      string `json:"base"`
	Candidate string `json:"candidate"`
}
type FuzzFunction struct {
	Path           string              `json:"path"`
	Line           int                 `json:"line"`
	EndLine        int                 `json:"end_line"`
	Symbol         string              `json:"symbol"`
	Signature      string              `json:"signature"`
	TestName       string              `json:"test_name,omitempty"`
	Outcome        string              `json:"outcome"`
	Reason         string              `json:"reason,omitempty"`
	EvidenceID     string              `json:"evidence_id,omitempty"`
	Checks         *FuzzChecks         `json:"checks,omitempty"`
	Counterexample *FuzzCounterexample `json:"counterexample,omitempty"`
	ResultsSHA256  string              `json:"results_sha256,omitempty"` // stream kept only as an artifact (budget overflow)
	Inputs         int                 `json:"inputs"`
	Compared       int                 `json:"compared"`
	Diverged       int                 `json:"diverged"`
	Unstable       int                 `json:"unstable"`
	Unconfirmed    int                 `json:"unconfirmed"`
	NotRecorded    int                 `json:"not_recorded"`
}
type FuzzSkip struct {
	Path   string `json:"path"`
	Line   int    `json:"line"`
	Symbol string `json:"symbol"`
	Reason string `json:"reason"`
}

// FuzzReport is the differential fuzzing section. It is present exactly when
// the policy has fuzz in review mode.
type FuzzReport struct {
	Status       string         `json:"status"`
	Reason       string         `json:"reason,omitempty"`
	SeedScheme   string         `json:"seed_scheme"`
	Limits       FuzzLimits     `json:"limits"`
	Functions    []FuzzFunction `json:"functions"`
	Skipped      []FuzzSkip     `json:"skipped"`
	SkippedTotal int            `json:"skipped_total"`
	Note         string         `json:"note"`
}
