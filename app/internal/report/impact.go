package report

import (
	"bytes"

	"github.com/gvinsot/SwiftProof/app/internal/model"
)

// This file belongs to F6a (symbol index / impact analysis), except
// verifyImpactedTests, which belongs to F6b. The F0 bodies below are
// behavior-safe stubs: they verify nothing and render nothing, and impacted
// tests that did not run request human review.

// verifyImpactedTests re-derives the status of every
// impacted_test_differential evidence record from its recorded checks (F6b).
func verifyImpactedTests(r *model.Report, l *ledger) map[string]string {
	return nil
}

// finalizeImpact sets each impacted test's status from the verified ledger.
// It may mutate only r.Impact, must be idempotent, and returns true when the
// section needs a human (F6a/F6b).
func finalizeImpact(r *model.Report, l *ledger) bool {
	return r.Impact != nil && r.Impact.TestsStatus == model.ImpactTestsNotRun
}

// impactTargets returns the review targets of the impact section (F6b).
func impactTargets(r *model.Report) []extraTarget {
	return nil
}

// writeImpact renders "## Impact Analysis" when r.Impact is present (F6a).
func writeImpact(b *bytes.Buffer, r *model.Report) {}
