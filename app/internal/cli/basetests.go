package cli

// F0 stub of the baseline-versions-of-changed-tests stage (F3 owns this file).
// A requested stage fails closed: the section is recorded as not_run, which
// requests human review under --ci, and nothing is claimed.

import (
	"context"
	"io"

	"github.com/gvinsot/SwiftProof/app/internal/gitrepo"
	"github.com/gvinsot/SwiftProof/app/internal/harness"
	"github.com/gvinsot/SwiftProof/app/internal/model"
)

// runBaseTests runs the baseline versions of changed Go tests on candidate
// code (--base-tests). It returns true on an operational failure. The stub
// records not_run.
func runBaseTests(ctx context.Context, repo *gitrepo.Repository, change model.Change, h *harness.Harness, r *model.Report, errOut io.Writer) (operational bool) {
	r.BaseTests = baseTestsSection(model.BaseTestsNotRun, "not implemented in this build")
	return false
}

// baseTestsSection builds a base-tests section with no items.
func baseTestsSection(status, reason string) *model.BaseTests {
	return &model.BaseTests{Status: status, Reason: reason, Tests: []model.BaseTest{}, Note: model.BaseTestsNote}
}

// recordBaseTestsSkipped records why a requested --base-tests stage did not run
// (§1.7). It is a no-op in lint, when not requested, or when the section is
// already set. --checks=false cannot occur: the flags reject it with exit 3.
func recordBaseTestsSkipped(sc stageContext, requested bool, r *model.Report) {
	if sc.mode != "review" || !requested || r.BaseTests != nil {
		return
	}
	if sc.reason == reasonNoChangedFiles {
		r.BaseTests = baseTestsSection(model.BaseTestsNoCandidates, "no changed files")
		return
	}
	r.BaseTests = baseTestsSection(model.BaseTestsNotRun, skippedReason(sc))
}

// baseTestsLine is the stdout line of the base-tests section; the stub prints none.
func baseTestsLine(b *model.BaseTests) string { return "" }
