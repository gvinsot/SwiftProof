package report

import (
	"sort"
	"strings"

	"github.com/gvinsot/SwiftProof/app/internal/harness"
	"github.com/gvinsot/SwiftProof/app/internal/model"
	"github.com/gvinsot/SwiftProof/app/internal/redact"
)

// ledger indexes the recorded checks and evidence of one report, so that every
// verifier resolves IDs the same way, and collects the evidence statuses that
// the verifiers re-derived from recorded checks. Only statuses in verified may
// support a hypothesis, a divergence or a section item.
type ledger struct {
	checks            map[string]model.Check // r.Checks only (mutation checks are verified by verifyMutation)
	duplicateChecks   map[string]bool
	evidence          map[string]model.Evidence
	duplicateEvidence map[string]bool
	verified          map[string]string // evidence ID -> status re-derived from recorded checks
	// rejected holds IDs a merge refused (a disagreement, a status that differs
	// from the stored one, or a kind the verifier does not own). A rejected ID
	// is never verified again in this ledger: the failure stays closed.
	rejected map[string]bool
}

// verifyReport builds the ledger of r and runs every evidence verifier and the
// masks, in the order Finalize uses. Its verified map is the only source of
// evidence statuses that may support anything; the Markdown renderer re-runs
// it so that what it prints agrees with what Finalize accepted.
func verifyReport(r *model.Report) *ledger {
	l := newLedger(r)
	l.mergeOwned(verifyCoreEvidence(r, l), model.EvidenceSourceObservation, model.EvidenceDifferentialTest)
	l.mergeOwned(verifyObservations(r, l), model.EvidenceDifferentialObservation)   // F1
	l.mergeOwned(verifyFuzz(r, l), model.EvidenceDifferentialFuzz)                  // F2
	l.mergeOwned(verifyBaseTests(r, l), model.EvidenceBaseTestDifferential)         // F3
	l.mergeOwned(verifyImpactedTests(r, l), model.EvidenceImpactedTestDifferential) // F6b
	l.mergeOwned(verifyIntentTests(r, l), model.EvidenceIntentTest)                 // F5
	l.applyMasks(observationMasks(r, l))                                            // F0 + F1 feed
	return l
}

// newLedger indexes r.Checks and r.Evidence. An ID recorded more than once is
// marked duplicated, and every lookup of it fails.
func newLedger(r *model.Report) *ledger {
	l := &ledger{
		checks:            make(map[string]model.Check, len(r.Checks)),
		duplicateChecks:   map[string]bool{},
		evidence:          make(map[string]model.Evidence, len(r.Evidence)),
		duplicateEvidence: map[string]bool{},
		verified:          map[string]string{},
		rejected:          map[string]bool{},
	}
	for _, c := range r.Checks {
		if _, exists := l.checks[c.ID]; exists {
			l.duplicateChecks[c.ID] = true
		}
		l.checks[c.ID] = c
	}
	for _, e := range r.Evidence {
		if _, exists := l.evidence[e.ID]; exists {
			l.duplicateEvidence[e.ID] = true
		}
		l.evidence[e.ID] = e
	}
	return l
}

// check returns the recorded check with this ID. It is false when the ID is
// missing, empty or recorded more than once. Callers must not modify the
// returned check's slices: they share memory with the report.
func (l *ledger) check(id string) (model.Check, bool) {
	c, ok := l.checks[id]
	if !ok || id == "" || l.duplicateChecks[id] {
		return model.Check{}, false
	}
	return c, true
}

// item returns the evidence record with this ID. It is false when the ID is
// missing, empty or recorded more than once. Callers must not modify the
// returned record's slices.
func (l *ledger) item(id string) (model.Evidence, bool) {
	e, ok := l.evidence[id]
	if !ok || id == "" || l.duplicateEvidence[id] {
		return model.Evidence{}, false
	}
	return e, true
}

// merge adds the statuses one verifier re-derived. It fails closed: an ID that
// does not resolve, a status that differs from the stored Evidence.Status, and
// an ID two verifiers disagree on are removed from verified and never
// re-admitted.
func (l *ledger) merge(m map[string]string) {
	for id, status := range m {
		l.admit(id, status)
	}
}

// mergeOwned is merge for a verifier that owns the given evidence kinds. An ID
// whose record has another kind is a verifier defect: it is rejected, and any
// status another verifier recorded for it is withdrawn.
func (l *ledger) mergeOwned(m map[string]string, kinds ...string) {
	owned := map[string]bool{}
	for _, k := range kinds {
		owned[k] = true
	}
	for id, status := range m {
		if e, ok := l.item(id); !ok || !owned[e.Kind] {
			l.reject(id)
			continue
		}
		l.admit(id, status)
	}
}

// admit records one verifier's status for id. Every admitted status equals the
// stored one, so two verifiers can only disagree when one of them returns a
// different status, and that rejects the ID for good.
func (l *ledger) admit(id, status string) {
	if l.rejected[id] {
		return
	}
	e, ok := l.item(id)
	if !ok || status == "" || e.Status != status {
		l.reject(id)
		return
	}
	l.verified[id] = status
}

func (l *ledger) reject(id string) {
	l.rejected[id] = true
	delete(l.verified, id)
}

// applyMasks withdraws a verified differential_test NOT_REPRODUCED when the
// generated test's candidate run also recorded a behavior difference, so that
// an observed difference can never be hidden behind a both-pass generated
// test. The rules are:
//   - (a) a verified DIVERGED differential_observation has the same CheckID;
//   - (b) its CheckID is in masked, the set observationMasks returns (every
//     candidate check whose observation record, whatever its verified status,
//     recorded a key on both sides with different full values).
func (l *ledger) applyMasks(masked map[string]bool) {
	diverged := map[string]bool{}
	for id, status := range l.verified {
		if status != model.StatusDiverged {
			continue
		}
		if e, ok := l.item(id); ok && e.Kind == model.EvidenceDifferentialObservation && e.CheckID != "" {
			diverged[e.CheckID] = true
		}
	}
	for id, status := range l.verified {
		if status != model.StatusNotReproduced {
			continue
		}
		e, ok := l.item(id)
		if !ok || e.Kind != model.EvidenceDifferentialTest {
			continue
		}
		if diverged[e.CheckID] || masked[e.CheckID] {
			delete(l.verified, id)
		}
	}
}

// positiveBaseline reports whether a baseline check may support a positive
// status (REPRODUCED, DIVERGED, FAILS_ON_CANDIDATE): it must have been executed
// in this run, never replayed from the execution cache.
func positiveBaseline(c model.Check) bool { return !c.Replayed() }

// negativeBaseline reports whether a baseline check may support a negative
// status (NOT_REPRODUCED, NOT_DIVERGED, PASSES_ON_CANDIDATE): executed in this
// run, or replayed from a cache entry that two agreeing live runs recorded.
func negativeBaseline(c model.Check) bool {
	return !c.Replayed() || c.Cache.LiveRuns >= 2
}

// verifiableText reports whether a string an evidence record uses to select
// recorded results (a test name, a test path) survives report sanitizing
// unchanged and was not produced by it: it is a fixed point of redact.Redact
// and holds no redaction marker. Anything else could select different results
// before and after a re-render, so it supports nothing; this keeps Finalize
// idempotent and stops two names that redact alike from being confused.
func verifiableText(s string) bool {
	return redact.IsFixedPoint(s) && !strings.Contains(s, redact.Marker)
}

// verifiableNames applies verifiableText to every name. It is false for an
// empty list.
func verifiableNames(names []string) bool {
	for _, n := range names {
		if !verifiableText(n) {
			return false
		}
	}
	return len(names) > 0
}

// verifyCoreEvidence re-derives the two v0.2 evidence kinds.
//   - source_observation: OBSERVED when the record carries the observed text.
//   - differential_test: the v0.2 validation, unchanged (base kind
//     generated_test_base, candidate kind generated_test_candidate, equal
//     non-empty commands, a validated named execution, a passing baseline),
//     plus the live-baseline rule. REPRODUCED needs a candidate FAIL with exit
//     1..124 and a baseline that was not replayed; NOT_REPRODUCED needs a
//     candidate PASS with exit 0 and a baseline that was live or replayed from
//     two agreeing live runs. A replayed candidate check, which the harness
//     never records, supports nothing, and so do test names or a path that
//     report sanitizing would change (see verifiableText).
func verifyCoreEvidence(r *model.Report, l *ledger) map[string]string {
	out := map[string]string{}
	for _, recorded := range r.Evidence {
		e, ok := l.item(recorded.ID)
		if !ok {
			continue
		}
		status := ""
		switch e.Kind {
		case model.EvidenceSourceObservation:
			if e.Output != "" {
				status = model.StatusObserved
			}
		case model.EvidenceDifferentialTest:
			status = differentialTestStatus(e, l)
		}
		if status != "" && status == e.Status {
			out[e.ID] = status
		}
	}
	return out
}

// differentialTestStatus is the status the recorded checks of one generated
// test support, or "" when they support none.
func differentialTestStatus(e model.Evidence, l *ledger) string {
	if !verifiableNames(e.TestNames) || e.Path != "" && !verifiableText(e.Path) {
		return ""
	}
	base, baseOK := l.check(e.BaseCheckID)
	candidate, candidateOK := l.check(e.CheckID)
	if !baseOK || !candidateOK || base.Kind != model.CheckGeneratedBase || candidate.Kind != model.CheckGeneratedCandidate || !equalCommand(candidate.Command, base.Command) || candidate.Replayed() {
		return ""
	}
	candidate, known := harness.ValidateExecution(e.Runner, candidate, e.Path, e.TestNames)
	base, _ = harness.ValidateExecution(e.Runner, base, e.Path, e.TestNames)
	if !known || base.Status != "PASS" || base.ExitCode != 0 {
		return ""
	}
	switch {
	case candidate.Status == "FAIL" && candidate.ExitCode > 0 && candidate.ExitCode < 125 && positiveBaseline(base):
		return model.StatusReproduced
	case candidate.Status == "PASS" && candidate.ExitCode == 0 && negativeBaseline(base):
		return model.StatusNotReproduced
	}
	return ""
}

// accepted lists, per claimed hypothesis status, the (evidence kind, verified
// evidence status) pairs that can support it. Nothing else supports anything:
// NOT_DIVERGED, base_test_differential, impacted_test_differential,
// INTENT_TEST_PASSED, signals, coverage, mutants, impact, cache and prepare
// records never support a hypothesis status.
var accepted = map[string][]struct{ kind, status string }{
	model.StatusReproduced:       {{model.EvidenceDifferentialTest, model.StatusReproduced}},
	model.StatusDiverged:         {{model.EvidenceDifferentialObservation, model.StatusDiverged}, {model.EvidenceDifferentialFuzz, model.StatusDiverged}},
	model.StatusIntentTestFailed: {{model.EvidenceIntentTest, model.StatusIntentTestFailed}}, // + e.CriterionID == h.CriterionID, criterion present exactly once
	model.StatusNotReproduced:    {{model.EvidenceDifferentialTest, model.StatusNotReproduced}},
	model.StatusDismissed:        {{model.EvidenceSourceObservation, model.StatusObserved}}, // + non-blank rationale (checked by Finalize)
}

// supports reports whether a hypothesis's citations are well formed (valid:
// at least one evidence ID, and every cited ID resolves to exactly one
// record) and whether at least one cited record's (kind, verified status) pair
// is accepted for the claimed status (supported). An INTENT_TEST_FAILED claim
// additionally needs the record's criterion to be the hypothesis's criterion,
// and that criterion to occur exactly once in the report's criteria.
func (l *ledger) supports(h *model.Hypothesis, claimed string, criteria map[string]model.IntentCriterion) (valid, supported bool) {
	valid = len(h.EvidenceIDs) > 0
	pairs := accepted[claimed]
	for _, id := range h.EvidenceIDs {
		e, ok := l.item(id)
		if !ok {
			valid = false
			continue
		}
		status, verified := l.verified[id]
		if !verified {
			continue
		}
		for _, p := range pairs {
			if e.Kind != p.kind || status != p.status {
				continue
			}
			if claimed == model.StatusIntentTestFailed {
				if _, known := criteria[h.CriterionID]; !known || e.CriterionID != h.CriterionID {
					continue
				}
			}
			supported = true
		}
	}
	return valid, supported
}

// criterionIndex returns the acceptance criteria whose ID is valid and occurs
// exactly once. A duplicated ID supports nothing.
func criterionIndex(criteria []model.IntentCriterion) map[string]model.IntentCriterion {
	count := map[string]int{}
	for _, c := range criteria {
		count[c.ID]++
	}
	out := map[string]model.IntentCriterion{}
	for _, c := range criteria {
		if model.ValidCriterionID(c.ID) && count[c.ID] == 1 {
			out[c.ID] = c
		}
	}
	return out
}

// extraTarget is a human review target that a v0.4 section contributes from
// Finalize-derived data. severity is low, medium, high or critical; side is
// "new" or "old".
type extraTarget struct {
	path, side string
	start, end int
	severity   string
	reason     string
}

// extraTargets concatenates the section targets in a fixed order.
func extraTargets(r *model.Report) []extraTarget {
	var out []extraTarget
	out = append(out, baseTestTargets(r)...) // F3
	out = append(out, impactTargets(r)...)   // F6b
	out = append(out, fuzzTargets(r)...)     // F2
	return out
}

const (
	// maxDivergenceRows caps the DIVERGED rows kept per divergence entry.
	maxDivergenceRows = 32
	// Anchor sources of a divergence entry.
	anchorChangedFunction = "changed_function"
	anchorHypothesis      = "hypothesis"
)

// minDivergenceChecks is the number of check IDs a divergence of this kind
// must cite: base, candidate and repeat for an observation; base, candidate,
// base confirmation and candidate confirmation for a fuzz experiment. It is 0
// for any other kind.
func minDivergenceChecks(kind string) int {
	switch kind {
	case model.EvidenceDifferentialObservation:
		return 3
	case model.EvidenceDifferentialFuzz:
		return 4
	}
	return 0
}

// buildDivergences collects the divergence candidates of both feeds and keeps
// only the validated ones (see selectDivergences).
func buildDivergences(r *model.Report, l *ledger) []model.Divergence {
	var feed []model.Divergence
	feed = append(feed, observationDivergences(r, l)...) // F1
	feed = append(feed, fuzzDivergences(r, l)...)        // F2
	return selectDivergences(r, l, feed)
}

// selectDivergences keeps a candidate entry only when its evidence resolves,
// has the entry's kind and verified status DIVERGED, the entry has at least
// one DIVERGED row with a non-empty test and key, and it cites at least the
// kind's minimum number of check IDs, each resolving in the ledger. The test
// path and names fall back to the evidence record's; an entry still without a
// test path, or with an empty test name, is dropped, so every kept entry is
// schema-valid. It keeps DIVERGED rows only (at most maxDivergenceRows), keeps
// a fuzz entry's changed-function anchor only when its path names a changed,
// non-deleted file, sets the fixed note, and orders entries by the position of
// their evidence in r.Evidence, one entry per evidence ID. It does not read the
// hypotheses: linkDivergences cites and anchors through them once their
// statuses are final.
func selectDivergences(r *model.Report, l *ledger, feed []model.Divergence) []model.Divergence {
	position := map[string]int{}
	for i, e := range r.Evidence {
		if _, seen := position[e.ID]; !seen {
			position[e.ID] = i
		}
	}
	live := liveChangedPaths(r)
	kept := map[string]bool{}
	var out []model.Divergence
	for _, d := range feed {
		if kept[d.EvidenceID] {
			continue
		}
		e, ok := l.item(d.EvidenceID)
		minimum := minDivergenceChecks(d.Kind)
		if !ok || minimum == 0 || e.Kind != d.Kind || l.verified[d.EvidenceID] != model.StatusDiverged || len(d.CheckIDs) < minimum {
			continue
		}
		resolved := true
		for _, id := range d.CheckIDs {
			if _, ok := l.check(id); !ok {
				resolved = false
			}
		}
		if !resolved {
			continue
		}
		rows := []model.Observation{}
		for _, o := range d.Observations {
			if o.Status == model.ObservationDiverged && o.Test != "" && o.Key != "" && len(rows) < maxDivergenceRows {
				rows = append(rows, o)
			}
		}
		if len(rows) == 0 {
			continue
		}
		entry := model.Divergence{
			EvidenceID:    d.EvidenceID,
			Kind:          d.Kind,
			TestPath:      d.TestPath,
			TestNames:     append([]string{}, d.TestNames...),
			CheckIDs:      append([]string{}, d.CheckIDs...),
			HypothesisIDs: []string{},
			Observations:  rows,
			Note:          model.DivergenceNote,
		}
		if entry.TestPath == "" {
			entry.TestPath = e.Path
		}
		if len(entry.TestNames) == 0 {
			entry.TestNames = append(entry.TestNames, e.TestNames...)
		}
		if entry.TestPath == "" || len(entry.TestNames) == 0 || hasEmpty(entry.TestNames) {
			continue
		}
		// A fuzz entry keeps the changed function its feed selected, when that
		// function's file is a changed, non-deleted file; an observation entry
		// is anchored only through a citing hypothesis (linkDivergences).
		if d.Kind == model.EvidenceDifferentialFuzz && d.Path != "" && live[d.Path] {
			entry.Path, entry.Line, entry.Symbol, entry.AnchorSource = d.Path, d.Line, d.Symbol, anchorChangedFunction
		}
		kept[d.EvidenceID] = true
		out = append(out, entry)
	}
	sort.SliceStable(out, func(i, j int) bool { return position[out[i].EvidenceID] < position[out[j].EvidenceID] })
	return out
}

// linkDivergences sets each entry's HypothesisIDs to the hypotheses whose final
// status is DIVERGED and which cite the entry, sorted, and anchors an
// unanchored observation entry at the lowest-index such hypothesis whose path
// names a changed, non-deleted file. It must run after the hypothesis statuses
// are final. It returns the entries, modified in place.
func linkDivergences(r *model.Report, entries []model.Divergence) []model.Divergence {
	live := liveChangedPaths(r)
	for i := range entries {
		entry := &entries[i]
		var citing []string
		for _, h := range r.Hypotheses {
			if h.Status != model.StatusDiverged || !cites(h, entry.EvidenceID) {
				continue
			}
			citing = append(citing, h.ID)
			if entry.Kind == model.EvidenceDifferentialObservation && entry.Path == "" && h.Path != "" && live[h.Path] {
				entry.Path, entry.Line, entry.AnchorSource = h.Path, h.Line, anchorHypothesis
			}
		}
		entry.HypothesisIDs = unique(citing)
	}
	return entries
}

func cites(h model.Hypothesis, id string) bool {
	for _, cited := range h.EvidenceIDs {
		if cited == id {
			return true
		}
	}
	return false
}

// citesAny reports whether h cites at least one evidence ID in ids.
func citesAny(h model.Hypothesis, ids map[string]bool) bool {
	for _, cited := range h.EvidenceIDs {
		if ids[cited] {
			return true
		}
	}
	return false
}

func hasEmpty(values []string) bool {
	for _, v := range values {
		if v == "" {
			return true
		}
	}
	return false
}

// liveChangedPaths returns the candidate-side paths of the changed files that
// still exist on the candidate (every status except deleted).
func liveChangedPaths(r *model.Report) map[string]bool {
	out := map[string]bool{}
	for _, f := range r.Change.Files {
		if f.Path != "" && f.Status != "D" {
			out[f.Path] = true
		}
	}
	return out
}
