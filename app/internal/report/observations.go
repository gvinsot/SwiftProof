package report

import "github.com/gvinsot/SwiftProof/app/internal/model"

// This file belongs to F1 (observation oracle). The F0 bodies below are
// behavior-safe stubs: they verify nothing, feed no divergence and mask
// nothing, so a differential_observation record supports no hypothesis.

// verifyObservations re-derives the status of every differential_observation
// evidence record from its recorded checks. It returns an ID only when the
// re-derived status equals the stored one (F1).
func verifyObservations(r *model.Report, l *ledger) map[string]string {
	return nil
}

// observationDivergences returns one candidate divergence per verified
// DIVERGED differential_observation record: Kind, TestPath, TestNames,
// CheckIDs [base, candidate, repeat] and the DIVERGED rows sorted by (test,
// key). Path stays empty; Finalize anchors it (F1).
func observationDivergences(r *model.Report, l *ledger) []model.Divergence {
	return nil
}

// observationMasks returns every candidate check ID whose observation record,
// whatever its verified status, recorded a key on both the baseline and the
// candidate side with different full values (F1).
func observationMasks(r *model.Report, l *ledger) map[string]bool {
	return nil
}
