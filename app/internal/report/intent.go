package report

import (
	"bytes"
	"fmt"

	"github.com/gvinsot/SwiftProof/app/internal/model"
	"github.com/gvinsot/SwiftProof/app/internal/redact"
)

// This file belongs to F5 (intent-linked candidate-only tests). The F0 bodies
// below are behavior-safe stubs: they verify nothing and render nothing, so an
// intent_test record supports no hypothesis. normalizeIntentLink already
// removes every intent link the schema would reject.

// verifyIntentTests re-derives the status of every intent_test evidence
// record from its recorded candidate check (F5).
func verifyIntentTests(r *model.Report, l *ledger) map[string]string {
	return nil
}

// normalizeIntentLink runs after a hypothesis's final status is set. It drops
// a criterion_id that is not in criteria, and drops intent_judgment unless the
// status is DIVERGED, the hypothesis keeps a criterion and the judgment is one
// of the two allowed values. Any drop returns one fixed Unverified note naming
// the hypothesis, "" otherwise. A second call finds nothing to drop, so
// Finalize stays idempotent. It never changes the status. F5 may refine the
// note text; these rules keep every hypothesis schema-valid.
func normalizeIntentLink(h *model.Hypothesis, criteria map[string]model.IntentCriterion) string {
	dropped := false
	if h.CriterionID != "" {
		if _, known := criteria[h.CriterionID]; !known {
			h.CriterionID = ""
			dropped = true
		}
	}
	if h.IntentJudgment != "" {
		allowed := h.IntentJudgment == model.JudgmentExpectedChange || h.IntentJudgment == model.JudgmentUnexpectedChange
		if !allowed || h.Status != model.StatusDiverged || h.CriterionID == "" {
			h.IntentJudgment = ""
			dropped = true
		}
	}
	if !dropped {
		return ""
	}
	return fmt.Sprintf("The intent link of hypothesis %s was discarded: an intent judgment is kept only on a DIVERGED hypothesis with a known criterion, and a criterion only when the intent defines it.", redact.TruncateUTF8(h.ID, 64))
}

// writeIntentSections renders "## Intent Test Failures" and "## Intent
// Criteria" (F5).
func writeIntentSections(b *bytes.Buffer, r *model.Report) {}

// writeIntentLink renders a hypothesis's criterion link, and its
// intent_judgment with the fixed label "Model judgment (not evidence)", after
// the hypothesis's own lines (F5).
func writeIntentLink(b *bytes.Buffer, r *model.Report, h model.Hypothesis) {}
