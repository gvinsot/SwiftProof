package model

// Impact section statuses, impacted-test statuses, change classes and edge
// resolutions.
const (
	ImpactNotApplicable     = "not_applicable"
	ImpactIndexed           = "indexed"
	ImpactLimited           = "limited"
	ImpactUnavailable       = "unavailable"
	ImpactTestsRan          = "ran"
	ImpactTestsNoCandidates = "no_candidates"
	ImpactTestsNotRun       = "not_run"
	ChangeBodyChanged       = "body_changed"
	ChangeSignatureChanged  = "signature_changed"
	ResolutionStatic        = "static"
	ResolutionInterface     = "interface"
)

// ImpactNote is the fixed note of the impact section. F6a owns its final text;
// this neutral sentence makes no claim.
const ImpactNote = "See the documentation for what this section does and does not establish."

type ImpactCaller struct {
	Path       string `json:"path"`
	Line       int    `json:"line"`
	Symbol     string `json:"symbol"`
	Depth      int    `json:"depth"`
	Resolution string `json:"resolution"`
}
type ImpactTest struct {
	Name       string `json:"name"`
	Path       string `json:"path"`
	Line       int    `json:"line"`
	Package    string `json:"package"`
	Depth      int    `json:"depth"`
	Resolution string `json:"resolution"`
	EvidenceID string `json:"evidence_id,omitempty"`
	Status     string `json:"status,omitempty"` // set by Finalize from verified evidence; empty when not run
	Reason     string `json:"reason,omitempty"`
}
type ImpactFunction struct {
	Path         string         `json:"path"`
	Line         int            `json:"line"`
	EndLine      int            `json:"end_line"`
	Symbol       string         `json:"symbol"`
	Change       string         `json:"change"`
	Callers      []ImpactCaller `json:"callers"`       // at most 10 listed
	CallersTotal int            `json:"callers_total"` // found by the bounded index search
	Tests        []ImpactTest   `json:"tests"`
}

// Impact is the impact-analysis section. It is present in lint and review
// unless --impact=false; TestsStatus is present only with --impacted-tests.
type Impact struct {
	Status           string           `json:"status"`
	Reason           string           `json:"reason,omitempty"`
	IndexedFiles     int              `json:"indexed_files"`
	ChangedFunctions []ImpactFunction `json:"changed_functions"`
	TestsStatus      string           `json:"tests_status,omitempty"` // present only with --impacted-tests
	TestsReason      string           `json:"tests_reason,omitempty"`
	Note             string           `json:"note"`
}
