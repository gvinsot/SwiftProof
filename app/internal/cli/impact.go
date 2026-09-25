package cli

// F0 stub of the impact analysis (F6a owns this file; runImpactedTests and
// recordImpactedTestsSkipped belong to F6b). With --impact (the default) the
// section is present and says the index is unavailable, so "present means
// requested" holds; nothing is claimed and no signal is added.

import (
	"context"
	"io"

	"github.com/gvinsot/SwiftProof/app/internal/gitrepo"
	"github.com/gvinsot/SwiftProof/app/internal/harness"
	"github.com/gvinsot/SwiftProof/app/internal/model"
)

// impactResult is what the static impact analysis hands to the rest of the run.
type impactResult struct {
	report  *model.Impact       // nil with --impact=false
	signals []model.Signal      // impacted_caller / analysis_limited signals
	lookup  harness.SymbolIndex // nil when no index was built
}

// analyzeImpact builds the static symbol index of the change. It returns an
// error only when ctx is cancelled (exit 4).
func analyzeImpact(ctx context.Context, repo *gitrepo.Repository, change model.Change, enabled bool) (impactResult, error) {
	if err := ctx.Err(); err != nil {
		return impactResult{}, err
	}
	if !enabled {
		return impactResult{}, nil
	}
	return impactResult{report: &model.Impact{
		Status: model.ImpactUnavailable, Reason: "the symbol index is not implemented in this build",
		ChangedFunctions: []model.ImpactFunction{}, Note: model.ImpactNote,
	}}, nil
}

// runImpactedTests runs the unchanged tests that statically reach changed code
// on baseline and candidate (--impacted-tests, F6b). It returns true on an
// operational failure. The stub records tests_status not_run.
func runImpactedTests(ctx context.Context, h *harness.Harness, r *model.Report, res impactResult, errOut io.Writer) (operational bool) {
	if r.Impact != nil {
		r.Impact.TestsStatus, r.Impact.TestsReason = model.ImpactTestsNotRun, "not implemented in this build"
	}
	return false
}

// recordImpactedTestsSkipped records why a requested --impacted-tests stage did
// not run (§1.7, F6b). It is a no-op in lint, when not requested, without an
// impact section, or when tests_status is already set. --checks=false and
// --impact=false cannot occur: the flags reject them with exit 3.
func recordImpactedTestsSkipped(sc stageContext, requested bool, r *model.Report) {
	if sc.mode != "review" || !requested || r.Impact == nil || r.Impact.TestsStatus != "" {
		return
	}
	if sc.reason == reasonNoChangedFiles {
		r.Impact.TestsStatus, r.Impact.TestsReason = model.ImpactTestsNoCandidates, "no changed files"
		return
	}
	r.Impact.TestsStatus, r.Impact.TestsReason = model.ImpactTestsNotRun, skippedReason(sc)
}

// impactLine is the stdout line of the impact section; the stub prints none.
func impactLine(i *model.Impact) string { return "" }
