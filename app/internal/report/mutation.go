package report

import (
	"bytes"

	"github.com/gvinsot/SwiftProof/app/internal/model"
)

// This file belongs to F4 (mutation of added lines). The F0 bodies below are
// behavior-safe stubs: no mutant status is verified, so every SURVIVED or
// KILLED mutant is downgraded to INCONCLUSIVE, and the section requests human
// review unless it could only have produced nothing.

// verifyMutation returns mutant ID -> status for the mutants whose recorded
// mutation-ledger checks support their status. It must not mutate r (F4).
func verifyMutation(r *model.Report) map[string]string {
	return nil
}

// unverifiedMutantReason explains a status Finalize withdrew.
const unverifiedMutantReason = "the recorded mutation checks do not support this status"

// finalizeMutation turns every SURVIVED or KILLED mutant whose status is not
// in verified into INCONCLUSIVE (a status outside the known set as well),
// recomputes the counts, turns a "ran" section that now holds an INCONCLUSIVE
// or NOT_RUN mutant, or dropped candidates, into "incomplete", and returns
// true for status not_run or incomplete. It may mutate only r.Mutation and is
// idempotent (F4).
func finalizeMutation(r *model.Report, verified map[string]string) bool {
	m := r.Mutation
	if m == nil {
		return false
	}
	m.Killed, m.Survived, m.Invalid, m.TimedOut, m.Inconclusive, m.NotRun = 0, 0, 0, 0, 0, 0
	for i := range m.Mutants {
		mu := &m.Mutants[i]
		switch mu.Status {
		case model.MutantKilled, model.MutantSurvived:
			if verified[mu.ID] != mu.Status {
				mu.Status, mu.Reason = model.MutantInconclusive, unverifiedMutantReason
			}
		case model.MutantInvalid, model.MutantTimeout, model.MutantInconclusive, model.MutantNotRun:
		default:
			mu.Status, mu.Reason = model.MutantInconclusive, unverifiedMutantReason
		}
		switch mu.Status {
		case model.MutantKilled:
			m.Killed++
		case model.MutantSurvived:
			m.Survived++
		case model.MutantInvalid:
			m.Invalid++
		case model.MutantTimeout:
			m.TimedOut++
		case model.MutantInconclusive:
			m.Inconclusive++
		case model.MutantNotRun:
			m.NotRun++
		}
	}
	if m.Status == model.MutationRan && (m.Inconclusive > 0 || m.NotRun > 0 || m.Dropped > 0) {
		m.Status = model.MutationIncomplete
	}
	return m.Status == model.MutationNotRun || m.Status == model.MutationIncomplete
}

// writeMutation renders "## Mutation of Added Lines" when r.Mutation is
// present. Killed mutants are counted, never listed (F4).
func writeMutation(b *bytes.Buffer, r *model.Report) {}
