package report

import (
	"bytes"

	"github.com/gvinsot/SwiftProof/app/internal/model"
)

// This file belongs to F2 (deterministic differential fuzzing). The F0 bodies
// below are behavior-safe stubs: they verify nothing and render nothing, and a
// fuzz section that did not run requests human review.

// verifyFuzz re-derives the status of every differential_fuzz evidence record
// from its recorded checks (F2).
func verifyFuzz(r *model.Report, l *ledger) map[string]string {
	return nil
}

// finalizeFuzz reconciles r.Fuzz with the verified ledger. It may mutate only
// r.Fuzz, must be idempotent, and returns true when the section needs a human
// (F2).
func finalizeFuzz(r *model.Report, l *ledger) bool {
	return r.Fuzz != nil && r.Fuzz.Status == model.FuzzNotRun
}

// fuzzDivergences returns one candidate divergence per diverged function (F2).
func fuzzDivergences(r *model.Report, l *ledger) []model.Divergence {
	return nil
}

// fuzzTargets returns the review targets of the fuzz section (F2).
func fuzzTargets(r *model.Report) []extraTarget {
	return nil
}

// writeFuzz renders "## Differential Fuzzing" when r.Fuzz is present (F2).
func writeFuzz(b *bytes.Buffer, r *model.Report) {}
