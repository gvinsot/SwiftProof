package report

import (
	"bytes"

	"github.com/gvinsot/SwiftProof/app/internal/model"
)

// This file belongs to F5 (intent-linked candidate-only tests). The F0 bodies
// below are behavior-safe stubs: they verify nothing and render nothing, so an
// intent_test record supports no hypothesis.

// verifyIntentTests re-derives the status of every intent_test evidence
// record from its recorded candidate check (F5).
func verifyIntentTests(r *model.Report, l *ledger) map[string]string {
	return nil
}

// normalizeIntentLink runs after a hypothesis's final status is set. It drops
// intent_judgment unless the status is DIVERGED and drops a criterion_id that
// is not in criteria; each drop returns a fixed Unverified note, "" otherwise
// (F5).
func normalizeIntentLink(h *model.Hypothesis, criteria map[string]model.IntentCriterion) string {
	return ""
}

// writeIntentSections renders "## Intent Test Failures" and "## Intent
// Criteria" (F5).
func writeIntentSections(b *bytes.Buffer, r *model.Report) {}

// writeIntentLink renders a hypothesis's criterion link, and its
// intent_judgment with the fixed label "Model judgment (not evidence)", after
// the hypothesis's own lines (F5).
func writeIntentLink(b *bytes.Buffer, r *model.Report, h model.Hypothesis) {}
