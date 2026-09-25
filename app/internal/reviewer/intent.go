package reviewer

// F0 stub of the intent links (F5 owns this file). Without acceptance-criteria
// support, a hypothesis can carry neither a criterion nor a model judgment.

import (
	"errors"

	"github.com/gvinsot/SwiftProof/app/internal/model"
)

// intentPromptFor is appended to the system prompt; it explains the intent
// tests when the run has acceptance criteria. The stub adds nothing.
func intentPromptFor(withIntent bool) string { return "" }

// validateIntentLink checks a submitted hypothesis's criterion_id and
// intent_judgment against the run's acceptance criteria. The stub rejects any
// non-empty link.
func validateIntentLink(r *model.Report, h *model.Hypothesis) error {
	if h.CriterionID != "" || h.IntentJudgment != "" {
		return errors.New("intent links require acceptance criteria")
	}
	return nil
}
