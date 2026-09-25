package cli

// F0 stub of the differential fuzzing stage (F2 owns this file). A configured
// fuzz policy fails closed: the section is recorded as not_run, which requests
// human review under --ci, and nothing is claimed.

import (
	"context"
	"io"

	"github.com/gvinsot/SwiftProof/app/internal/config"
	"github.com/gvinsot/SwiftProof/app/internal/harness"
	"github.com/gvinsot/SwiftProof/app/internal/model"
)

// runFuzz runs differential fuzzing of changed Go functions when the policy has
// fuzz and --fuzz is not false. The stub records not_run.
func runFuzz(ctx context.Context, h *harness.Harness, cfg config.Config, change model.Change, baseDir, candidateDir string, r *model.Report, enabled bool, errOut io.Writer) {
	if cfg.Fuzz == nil || !enabled {
		return
	}
	r.Fuzz = fuzzSection(cfg, model.FuzzNotRun, "differential fuzzing is not implemented in this build")
}

// fuzzSection builds a fuzz section with no function results.
func fuzzSection(cfg config.Config, status, reason string) *model.FuzzReport {
	e := cfg.Fuzz.Effective(cfg.Sandbox)
	return &model.FuzzReport{
		Status: status, Reason: reason, SeedScheme: model.FuzzSeedScheme,
		Limits:    model.FuzzLimits{MaxFunctions: e.MaxFunctions, MaxPackages: e.MaxPackages, MaxInputs: e.MaxInputs, CallTimeoutMS: e.CallTimeoutMS, MaxRuntimeSeconds: e.MaxRuntimeSeconds},
		Functions: []model.FuzzFunction{}, Skipped: []model.FuzzSkip{}, Note: model.FuzzNote,
	}
}

// recordFuzzSkipped records why a configured fuzz stage did not run (§1.7). It
// is a no-op in lint, without a fuzz policy, or when the section is already set.
// No changed files gives no_candidates; --fuzz=false or --checks=false, an
// explicit operator choice, gives disabled; any other missed execution gives
// not_run with the stage reason.
func recordFuzzSkipped(cfg config.Config, sc stageContext, enabled bool, r *model.Report) {
	if sc.mode != "review" || cfg.Fuzz == nil || r.Fuzz != nil {
		return
	}
	switch {
	case sc.reason == reasonNoChangedFiles:
		r.Fuzz = fuzzSection(cfg, model.FuzzNoCandidates, "no changed files")
	case !enabled:
		r.Fuzz = fuzzSection(cfg, model.FuzzDisabled, "--fuzz=false")
	case !sc.checks:
		r.Fuzz = fuzzSection(cfg, model.FuzzDisabled, "--checks=false")
	default:
		r.Fuzz = fuzzSection(cfg, model.FuzzNotRun, skippedReason(sc))
	}
}

// fuzzLine is the stdout line of the fuzz section; the stub prints none.
func fuzzLine(f *model.FuzzReport) string { return "" }
