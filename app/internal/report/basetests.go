package report

import (
	"bytes"

	"github.com/gvinsot/SwiftProof/app/internal/model"
)

// This file belongs to F3 (baseline versions of changed tests on candidate
// code). The F0 bodies below are behavior-safe stubs: they verify nothing and
// render nothing, and a section that did not run requests human review.

// verifyBaseTests re-derives the status of every base_test_differential
// evidence record from its recorded checks (F3).
func verifyBaseTests(r *model.Report, l *ledger) map[string]string {
	return nil
}

// finalizeBaseTests sets the base_tests item statuses from the verified
// ledger. It may mutate only r.BaseTests, must be idempotent, and returns true
// when the section needs a human (F3).
func finalizeBaseTests(r *model.Report, l *ledger) bool {
	return r.BaseTests != nil && r.BaseTests.Status == model.BaseTestsNotRun
}

// baseTestTargets returns the review targets of the base_tests section (F3).
func baseTestTargets(r *model.Report) []extraTarget {
	return nil
}

// writeBaseTests renders "## Changed Baseline Tests on Candidate Code" when
// r.BaseTests is present (F3).
func writeBaseTests(b *bytes.Buffer, r *model.Report) {}
