package model

// Model judgments a DIVERGED hypothesis may carry. They are never evidence.
const (
	JudgmentExpectedChange   = "expected_change"
	JudgmentUnexpectedChange = "unexpected_change"
)

// IntentCriterion is one acceptance criterion extracted verbatim from the intent.
type IntentCriterion struct {
	ID   string `json:"id"`   // AC-N
	Text string `json:"text"` // verbatim criterion text
	Line int    `json:"line"`
}

// ValidCriterionID reports whether id matches ^AC-[1-9][0-9]{0,2}$.
func ValidCriterionID(id string) bool {
	if len(id) < 4 || len(id) > 6 || id[:3] != "AC-" || id[3] < '1' || id[3] > '9' {
		return false
	}
	for i := 4; i < len(id); i++ {
		if id[i] < '0' || id[i] > '9' {
			return false
		}
	}
	return true
}
