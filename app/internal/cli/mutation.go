package cli

// F0 stub of the mutation stage (F4 owns this file). A configured mutation
// policy fails closed: the section is recorded as not_run, which requests
// human review under --ci, and nothing is claimed.

import (
	"context"
	"io"

	"github.com/gvinsot/SwiftProof/app/internal/config"
	"github.com/gvinsot/SwiftProof/app/internal/coverage"
	"github.com/gvinsot/SwiftProof/app/internal/harness"
	"github.com/gvinsot/SwiftProof/app/internal/model"
)

// runMutation mutates added Go lines and runs the policy's command once per
// mutant. It returns true on an operational failure. The stub records not_run.
func runMutation(ctx context.Context, h *harness.Harness, cfg config.Config, change model.Change, covered coverage.Result, r *model.Report, errOut io.Writer) (operational bool) {
	if cfg.Mutation == nil {
		return false
	}
	r.Mutation = mutationSection(cfg, model.MutationNotRun, "not implemented in this build")
	r.Unverified = append(r.Unverified, "Mutation analysis did not run: not implemented in this build")
	return false
}

// mutationSection builds a mutation section with no mutants.
func mutationSection(cfg config.Config, status, reason string) *model.Mutation {
	m := &model.Mutation{Status: status, Reason: reason, Command: []string{}, Files: []model.MutationFile{}, Mutants: []model.Mutant{}, Checks: []model.Check{}, Note: model.MutationNote}
	if cfg.Mutation != nil {
		m.Command = append(m.Command, cfg.Mutation.Command...)
		m.Limits = model.MutationLimits{MaxMutants: cfg.Mutation.MaxMutants, TimeoutSeconds: cfg.Mutation.TimeoutSeconds, MaxRuntimeSeconds: cfg.Mutation.MaxRuntimeSeconds}
	}
	return m
}

// recordMutationSkipped records why a configured mutation stage did not run
// (§1.7). It is a no-op in lint, without a mutation policy, or when the section
// is already set. No changed files gives no_candidates; --checks=false and any
// other missed execution give not_run with their reason.
func recordMutationSkipped(cfg config.Config, sc stageContext, r *model.Report) {
	if sc.mode != "review" || cfg.Mutation == nil || r.Mutation != nil {
		return
	}
	switch {
	case sc.reason == reasonNoChangedFiles:
		r.Mutation = mutationSection(cfg, model.MutationNoCandidates, "no changed files")
	case !sc.checks:
		r.Mutation = mutationSection(cfg, model.MutationNotRun, "initial checks disabled (--checks=false)")
	default:
		r.Mutation = mutationSection(cfg, model.MutationNotRun, skippedReason(sc))
	}
}

// mutationLine is the stdout line of the mutation section; the stub prints none.
func mutationLine(m *model.Mutation) string { return "" }
