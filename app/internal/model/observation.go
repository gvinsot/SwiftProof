package model

// Observation statuses of one recorded key compared across revisions.
const (
	ObservationEqual        = "EQUAL"
	ObservationDiverged     = "DIVERGED"
	ObservationUnstable     = "UNSTABLE"
	ObservationIncomparable = "INCOMPARABLE"
)

// Observation is one recorded key compared across revisions. Base and Candidate are
// display cuts (256 bytes, UTF-8 safe) of the experiment's own redacted, bounded
// serialization; comparison always uses the full recorded values, never these cuts.
type Observation struct {
	Test              string `json:"test"`
	Key               string `json:"key"` // F1: recorded key; F2: rendered input call expression
	Status            string `json:"status"`
	Base              string `json:"base"`
	Candidate         string `json:"candidate"`
	BaseRecorded      bool   `json:"base_recorded"`
	CandidateRecorded bool   `json:"candidate_recorded"`
	Truncated         bool   `json:"truncated,omitempty"`
	Reason            string `json:"reason,omitempty"`
}

// Divergence is a validated DIVERGED experiment of kind differential_observation
// or differential_fuzz. It records a difference, never which revision is right.
type Divergence struct {
	EvidenceID    string        `json:"evidence_id"`
	Kind          string        `json:"kind"`
	Path          string        `json:"path,omitempty"`
	Line          int           `json:"line,omitempty"`
	Symbol        string        `json:"symbol,omitempty"`
	AnchorSource  string        `json:"anchor_source,omitempty"` // "changed_function" | "hypothesis" (model-chosen)
	TestPath      string        `json:"test_path"`
	TestNames     []string      `json:"test_names"`
	CheckIDs      []string      `json:"check_ids"` // observation: base, candidate, repeat; fuzz: base, candidate, base_confirm, candidate_confirm
	HypothesisIDs []string      `json:"hypothesis_ids"`
	Observations  []Observation `json:"observations"` // DIVERGED rows only, 1..32
	Note          string        `json:"note"`
}

// DivergenceNote is the fixed note every divergence entry carries.
const DivergenceNote = "Recorded values differ between revisions for the same inputs: the candidate differed from baseline runs that agreed with each other. This does not establish which revision is correct."
