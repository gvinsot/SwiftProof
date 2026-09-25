package report

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/gvinsot/SwiftProof/app/internal/model"
)

// ledgerWith indexes a report holding only these evidence records and marks
// the given IDs verified, bypassing the verifiers.
func ledgerWith(evidence []model.Evidence, verified map[string]string) *ledger {
	l := newLedger(&model.Report{Evidence: evidence})
	for id, status := range verified {
		l.verified[id] = status
	}
	return l
}

func noDivergences(*model.Report, *ledger) []model.Divergence { return nil }

var (
	allEvidenceKinds = []string{
		model.EvidenceSourceObservation, model.EvidenceDifferentialTest, model.EvidenceDifferentialObservation,
		model.EvidenceDifferentialFuzz, model.EvidenceBaseTestDifferential, model.EvidenceImpactedTestDifferential,
		model.EvidenceIntentTest,
	}
	allEvidenceStatuses = []string{
		model.StatusObserved, model.StatusReproduced, model.StatusNotReproduced, model.StatusUnverified,
		model.StatusDiverged, model.StatusNotDiverged, model.StatusFailsOnCandidate, model.StatusPassesOnCandidate,
		model.StatusIntentTestFailed, model.StatusIntentTestPassed,
	}
	allClaims = []string{
		model.StatusReproduced, model.StatusDiverged, model.StatusIntentTestFailed, model.StatusNotReproduced,
		model.StatusDismissed, model.StatusUnverified, "APPROVED", "",
	}
)

func TestLedgerLookupsFailClosed(t *testing.T) {
	r := &model.Report{
		Checks:   []model.Check{{ID: "check-1"}, {ID: "check-2"}, {ID: "check-2"}, {ID: ""}},
		Evidence: []model.Evidence{{ID: "evidence-1"}, {ID: "evidence-2"}, {ID: "evidence-2"}, {ID: ""}},
	}
	l := newLedger(r)
	if _, ok := l.check("check-1"); !ok {
		t.Fatal("a unique check did not resolve")
	}
	for _, id := range []string{"check-2", "", "check-9"} {
		if _, ok := l.check(id); ok {
			t.Errorf("check %q resolved although it is duplicated, empty or missing", id)
		}
	}
	if _, ok := l.item("evidence-1"); !ok {
		t.Fatal("a unique evidence record did not resolve")
	}
	for _, id := range []string{"evidence-2", "", "evidence-9"} {
		if _, ok := l.item(id); ok {
			t.Errorf("evidence %q resolved although it is duplicated, empty or missing", id)
		}
	}
}

func TestLedgerMergeFailsClosed(t *testing.T) {
	evidence := []model.Evidence{
		{ID: "agreed", Kind: model.EvidenceDifferentialTest, Status: model.StatusReproduced},
		{ID: "disputed", Kind: model.EvidenceDifferentialTest, Status: model.StatusReproduced},
		{ID: "wrong-status", Kind: model.EvidenceDifferentialTest, Status: model.StatusNotReproduced},
		{ID: "upgraded", Kind: model.EvidenceDifferentialTest, Status: model.StatusNotReproduced},
		{ID: "dup", Kind: model.EvidenceSourceObservation, Status: model.StatusObserved},
		{ID: "dup", Kind: model.EvidenceSourceObservation, Status: model.StatusObserved},
		{ID: "empty-status", Kind: model.EvidenceDifferentialTest, Status: model.StatusReproduced},
		{ID: "foreign", Kind: model.EvidenceDifferentialTest, Status: model.StatusNotReproduced},
		{ID: "observation", Kind: model.EvidenceDifferentialObservation, Status: model.StatusDiverged},
	}
	l := newLedger(&model.Report{Evidence: evidence})
	l.merge(map[string]string{"agreed": model.StatusReproduced, "disputed": model.StatusReproduced, "foreign": model.StatusNotReproduced})
	l.merge(map[string]string{"agreed": model.StatusReproduced}) // a second verifier agreeing keeps it
	l.merge(map[string]string{"disputed": model.StatusNotReproduced})
	l.merge(map[string]string{"disputed": model.StatusReproduced}) // never re-admitted
	l.merge(map[string]string{"wrong-status": model.StatusReproduced})
	l.merge(map[string]string{"wrong-status": model.StatusNotReproduced}) // never re-admitted
	// A verifier may not upgrade a stored status, even when no one disputes it.
	l.merge(map[string]string{"upgraded": model.StatusReproduced})
	l.merge(map[string]string{"dup": model.StatusObserved, "missing": model.StatusObserved, "empty-status": ""})
	// A verifier that owns observations must not vouch for a differential_test,
	// and doing so withdraws what the owning verifier recorded.
	l.mergeOwned(map[string]string{"foreign": model.StatusNotReproduced, "observation": model.StatusDiverged}, model.EvidenceDifferentialObservation)
	want := map[string]string{"agreed": model.StatusReproduced, "observation": model.StatusDiverged}
	if len(l.verified) != len(want) {
		t.Fatalf("verified %v, want %v", l.verified, want)
	}
	for id, status := range want {
		if l.verified[id] != status {
			t.Fatalf("verified %v, want %v", l.verified, want)
		}
	}
	l.merge(map[string]string{"foreign": model.StatusNotReproduced})
	if _, ok := l.verified["foreign"]; ok {
		t.Fatal("an ID rejected for a foreign kind was re-admitted")
	}
}

func TestApplyMasks(t *testing.T) {
	evidence := []model.Evidence{
		{ID: "dt-a", Kind: model.EvidenceDifferentialTest, Status: model.StatusNotReproduced, CheckID: "c1"},
		{ID: "obs-a", Kind: model.EvidenceDifferentialObservation, Status: model.StatusDiverged, CheckID: "c1"},
		{ID: "dt-equal", Kind: model.EvidenceDifferentialTest, Status: model.StatusNotReproduced, CheckID: "c2"},
		{ID: "obs-equal", Kind: model.EvidenceDifferentialObservation, Status: model.StatusNotDiverged, CheckID: "c2"},
		{ID: "dt-b", Kind: model.EvidenceDifferentialTest, Status: model.StatusNotReproduced, CheckID: "c3"},
		{ID: "dt-reproduced", Kind: model.EvidenceDifferentialTest, Status: model.StatusReproduced, CheckID: "c4"},
		{ID: "dt-unverified-obs", Kind: model.EvidenceDifferentialTest, Status: model.StatusNotReproduced, CheckID: "c5"},
		{ID: "obs-unverified", Kind: model.EvidenceDifferentialObservation, Status: model.StatusDiverged, CheckID: "c5"},
		{ID: "fuzz", Kind: model.EvidenceDifferentialFuzz, Status: model.StatusDiverged, CheckID: "c6"},
		{ID: "dt-fuzz", Kind: model.EvidenceDifferentialTest, Status: model.StatusNotReproduced, CheckID: "c6"},
	}
	verified := map[string]string{}
	for _, e := range evidence {
		if e.ID != "obs-unverified" {
			verified[e.ID] = e.Status
		}
	}
	l := ledgerWith(evidence, verified)
	l.applyMasks(map[string]bool{"c3": true, "c4": true})
	for id, kept := range map[string]bool{
		"dt-a":              false, // rule (a): a verified DIVERGED observation shares its candidate check
		"dt-equal":          true,  // NOT_DIVERGED on the same check masks nothing by rule (a)
		"dt-b":              false, // rule (b): the F1 set names its candidate check
		"dt-reproduced":     true,  // masks withdraw NOT_REPRODUCED only
		"dt-unverified-obs": true,  // rule (a) needs a verified observation; rule (b) is F1's feed
		"dt-fuzz":           true,  // rule (a) concerns observations only
		"obs-a":             true,
		"obs-equal":         true,
		"fuzz":              true,
	} {
		if _, ok := l.verified[id]; ok != kept {
			t.Errorf("%s: kept=%v, want %v", id, ok, kept)
		}
	}
}

// Every (claimed status, evidence kind, verified evidence status) triple is
// checked against the table written out here, independently of accepted.
func TestAcceptanceTable(t *testing.T) {
	supporting := map[[3]string]bool{
		{model.StatusReproduced, model.EvidenceDifferentialTest, model.StatusReproduced}:       true,
		{model.StatusDiverged, model.EvidenceDifferentialObservation, model.StatusDiverged}:    true,
		{model.StatusDiverged, model.EvidenceDifferentialFuzz, model.StatusDiverged}:           true,
		{model.StatusIntentTestFailed, model.EvidenceIntentTest, model.StatusIntentTestFailed}: true,
		{model.StatusNotReproduced, model.EvidenceDifferentialTest, model.StatusNotReproduced}: true,
		{model.StatusDismissed, model.EvidenceSourceObservation, model.StatusObserved}:         true,
	}
	criteria := criterionIndex([]model.IntentCriterion{{ID: "AC-1", Text: "Orders of 100 or more get 10 off", Line: 3}})
	positives := 0
	for _, claimed := range allClaims {
		for _, kind := range allEvidenceKinds {
			for _, status := range allEvidenceStatuses {
				e := model.Evidence{ID: "evidence-1", Kind: kind, Status: status, CriterionID: "AC-1"}
				h := model.Hypothesis{ID: "h1", Status: claimed, EvidenceIDs: []string{"evidence-1"}, CriterionID: "AC-1"}
				valid, supported := ledgerWith([]model.Evidence{e}, map[string]string{"evidence-1": status}).supports(&h, claimed, criteria)
				want := supporting[[3]string{claimed, kind, status}]
				if !valid || supported != want {
					t.Errorf("claim %q with %s/%s: valid=%v supported=%v, want supported=%v", claimed, kind, status, valid, supported, want)
				}
				if want {
					positives++
				}
				// The same record without a verified status supports nothing.
				if _, supported := ledgerWith([]model.Evidence{e}, nil).supports(&h, claimed, criteria); supported {
					t.Errorf("claim %q with unverified %s/%s was supported", claimed, kind, status)
				}
			}
		}
	}
	if positives != len(supporting) {
		t.Fatalf("exercised %d supporting triples, want %d", positives, len(supporting))
	}
}

func TestNeverSupportingRecords(t *testing.T) {
	never := []model.Evidence{
		{ID: "e", Kind: model.EvidenceDifferentialObservation, Status: model.StatusNotDiverged},
		{ID: "e", Kind: model.EvidenceDifferentialFuzz, Status: model.StatusNotDiverged},
		{ID: "e", Kind: model.EvidenceBaseTestDifferential, Status: model.StatusFailsOnCandidate},
		{ID: "e", Kind: model.EvidenceBaseTestDifferential, Status: model.StatusPassesOnCandidate},
		{ID: "e", Kind: model.EvidenceImpactedTestDifferential, Status: model.StatusFailsOnCandidate},
		{ID: "e", Kind: model.EvidenceImpactedTestDifferential, Status: model.StatusPassesOnCandidate},
		{ID: "e", Kind: model.EvidenceIntentTest, Status: model.StatusIntentTestPassed, CriterionID: "AC-1"},
	}
	criteria := criterionIndex([]model.IntentCriterion{{ID: "AC-1", Text: "x"}})
	for _, e := range never {
		for _, claimed := range allClaims {
			h := model.Hypothesis{EvidenceIDs: []string{"e"}, CriterionID: "AC-1", Rationale: "looks equivalent"}
			if _, supported := ledgerWith([]model.Evidence{e}, map[string]string{"e": e.Status}).supports(&h, claimed, criteria); supported {
				t.Errorf("%s/%s supported %q", e.Kind, e.Status, claimed)
			}
		}
	}
}

func TestIntentTestFailedNeedsItsOwnUniqueCriterion(t *testing.T) {
	e := model.Evidence{ID: "e", Kind: model.EvidenceIntentTest, Status: model.StatusIntentTestFailed, CriterionID: "AC-1"}
	tests := []struct {
		name      string
		criteria  []model.IntentCriterion
		hCriteria string
		eCriteria string
		want      bool
	}{
		{"matching", []model.IntentCriterion{{ID: "AC-1"}, {ID: "AC-2"}}, "AC-1", "AC-1", true},
		{"other criterion", []model.IntentCriterion{{ID: "AC-1"}, {ID: "AC-2"}}, "AC-2", "AC-1", false},
		{"no hypothesis criterion", []model.IntentCriterion{{ID: "AC-1"}}, "", "AC-1", false},
		{"unknown criterion", []model.IntentCriterion{{ID: "AC-2"}}, "AC-1", "AC-1", false},
		{"duplicated criterion", []model.IntentCriterion{{ID: "AC-1"}, {ID: "AC-1"}}, "AC-1", "AC-1", false},
		{"invalid criterion", []model.IntentCriterion{{ID: "AC-01"}}, "AC-01", "AC-01", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := e
			e.CriterionID = tt.eCriteria
			h := model.Hypothesis{EvidenceIDs: []string{"e"}, CriterionID: tt.hCriteria}
			_, supported := ledgerWith([]model.Evidence{e}, map[string]string{"e": e.Status}).supports(&h, model.StatusIntentTestFailed, criterionIndex(tt.criteria))
			if supported != tt.want {
				t.Fatalf("supported=%v, want %v", supported, tt.want)
			}
		})
	}
}

func TestCriterionIndex(t *testing.T) {
	got := criterionIndex([]model.IntentCriterion{
		{ID: "AC-1", Text: "one", Line: 2}, {ID: "AC-2", Text: "two"}, {ID: "AC-2", Text: "again"},
		{ID: "AC-0"}, {ID: "AC-1000"}, {ID: "ac-3"}, {ID: ""}, {ID: "AC-999", Text: "last"},
	})
	if len(got) != 2 || got["AC-1"].Text != "one" || got["AC-1"].Line != 2 || got["AC-999"].Text != "last" {
		t.Fatalf("criterion index %+v", got)
	}
}

func TestSupportsValidity(t *testing.T) {
	e := model.Evidence{ID: "e", Kind: model.EvidenceDifferentialTest, Status: model.StatusReproduced}
	l := ledgerWith([]model.Evidence{e}, map[string]string{"e": e.Status})
	for _, tt := range []struct {
		name             string
		ids              []string
		valid, supported bool
	}{
		{"cited", []string{"e"}, true, true},
		{"none", nil, false, false},
		{"invented", []string{"invented"}, false, false},
		{"one invented", []string{"e", "invented"}, false, true},
		{"empty ID", []string{""}, false, false},
	} {
		h := model.Hypothesis{EvidenceIDs: tt.ids}
		valid, supported := l.supports(&h, model.StatusReproduced, nil)
		if valid != tt.valid || supported != tt.supported {
			t.Errorf("%s: valid=%v supported=%v, want %v %v", tt.name, valid, supported, tt.valid, tt.supported)
		}
	}
}

// conclude gives every claimed status its final form from the verified ledger.
func TestConcludeStatusesAndExitCodes(t *testing.T) {
	evidence := []model.Evidence{
		{ID: "reproduced", Kind: model.EvidenceDifferentialTest, Status: model.StatusReproduced},
		{ID: "observation", Kind: model.EvidenceDifferentialObservation, Status: model.StatusDiverged},
		{ID: "fuzz", Kind: model.EvidenceDifferentialFuzz, Status: model.StatusDiverged},
		{ID: "intent", Kind: model.EvidenceIntentTest, Status: model.StatusIntentTestFailed, CriterionID: "AC-1"},
		{ID: "negative", Kind: model.EvidenceDifferentialTest, Status: model.StatusNotReproduced},
		{ID: "not-diverged", Kind: model.EvidenceDifferentialObservation, Status: model.StatusNotDiverged},
		{ID: "source", Kind: model.EvidenceSourceObservation, Status: model.StatusObserved, Output: "if x < 0 { return err }"},
	}
	tests := []struct {
		name     string
		h        model.Hypothesis
		status   string
		exit     int // without --ci
		exitCI   int
		intent   bool
		targeted bool
	}{
		{"reproduced high", model.Hypothesis{Status: "reproduced", Severity: "high", EvidenceIDs: []string{"reproduced"}}, model.StatusReproduced, 1, 1, false, true},
		{"reproduced low", model.Hypothesis{Status: "REPRODUCED", Severity: "low", EvidenceIDs: []string{"reproduced"}}, model.StatusReproduced, 0, 0, false, true},
		{"diverged critical", model.Hypothesis{Status: "diverged", Severity: "critical", EvidenceIDs: []string{"observation"}}, model.StatusDiverged, 0, 2, false, true},
		{"fuzz diverged", model.Hypothesis{Status: "DIVERGED", Severity: "high", EvidenceIDs: []string{"fuzz"}}, model.StatusDiverged, 0, 2, false, true},
		{"diverged on a differential test", model.Hypothesis{Status: "DIVERGED", Severity: "high", EvidenceIDs: []string{"reproduced"}}, model.StatusUnverified, 0, 2, false, true},
		{"intent test failed", model.Hypothesis{Status: "INTENT_TEST_FAILED", Severity: "critical", EvidenceIDs: []string{"intent"}, CriterionID: "AC-1"}, model.StatusIntentTestFailed, 0, 2, true, true},
		{"not reproduced", model.Hypothesis{Status: "NOT_REPRODUCED", Severity: "high", EvidenceIDs: []string{"negative"}}, model.StatusNotReproduced, 0, 0, false, false},
		{"not reproduced from NOT_DIVERGED", model.Hypothesis{Status: "NOT_REPRODUCED", Severity: "high", EvidenceIDs: []string{"not-diverged"}}, model.StatusUnverified, 0, 2, false, true},
		{"dismissed from NOT_DIVERGED", model.Hypothesis{Status: "DISMISSED", Severity: "high", Rationale: "values were equal", EvidenceIDs: []string{"not-diverged"}}, model.StatusUnverified, 0, 2, false, true},
		{"dismissed", model.Hypothesis{Status: "DISMISSED", Severity: "high", Rationale: "The source checks the input.", EvidenceIDs: []string{"source"}}, model.StatusDismissed, 0, 0, false, false},
		{"dismissed without rationale", model.Hypothesis{Status: "DISMISSED", Severity: "high", Rationale: " \t", EvidenceIDs: []string{"source"}}, model.StatusUnverified, 0, 2, false, true},
		{"unknown claim", model.Hypothesis{Status: "APPROVED", Severity: "high", EvidenceIDs: []string{"reproduced"}}, model.StatusUnverified, 0, 2, false, true},
	}
	for _, tt := range tests {
		for _, ci := range []bool{false, true} {
			h := tt.h
			h.ID, h.Title, h.Path, h.Line = "h1", "Title "+tt.name, "calc/calc.go", 7
			r := &model.Report{Evidence: evidence, Hypotheses: []model.Hypothesis{h}, IntentCriteria: []model.IntentCriterion{{ID: "AC-1", Text: "x"}}}
			l := newLedger(r)
			for _, e := range evidence {
				l.verified[e.ID] = e.Status
			}
			conclude(r, l, ci, noDivergences)
			want := tt.exit
			if ci {
				want = tt.exitCI
			}
			if got := r.Hypotheses[0]; got.Status != tt.status || r.ExitCode != want {
				t.Errorf("%s (ci=%v): status %s exit %d, want %s %d", tt.name, ci, got.Status, r.ExitCode, tt.status, want)
			}
			if (len(r.ReproducedIssues) == 1) != (tt.status == model.StatusReproduced) || len(r.ReproducedIssues) > 1 {
				t.Errorf("%s: reproduced_issues %+v", tt.name, r.ReproducedIssues)
			}
			if (len(r.IntentTestFailures) == 1) != tt.intent || len(r.IntentTestFailures) > 1 {
				t.Errorf("%s: intent_test_failures %+v", tt.name, r.IntentTestFailures)
			}
			targeted := false
			for _, target := range r.ReviewTargets {
				targeted = targeted || target.Path == "calc/calc.go" && target.StartLine == 7
			}
			if targeted != tt.targeted {
				t.Errorf("%s: review target present=%v, want %v (%+v)", tt.name, targeted, tt.targeted, r.ReviewTargets)
			}
		}
	}
}

// goProof is a validated go_test_json differential experiment: the named test
// passes on the baseline check and fails on the candidate check.
func goProof(baseOutput, candidateOutput string) *model.Report {
	command := []string{"go", "test", "-json", "-count=1", "-run", "^TestRegression$", "."}
	return &model.Report{
		Checks: []model.Check{
			{ID: "check-1", Kind: model.CheckGeneratedBase, Status: "PASS", Command: command, Output: baseOutput},
			{ID: "check-2", Kind: model.CheckGeneratedCandidate, Status: "FAIL", ExitCode: 1, Command: command, Output: candidateOutput},
		},
		Evidence:   []model.Evidence{{ID: "evidence-1", Kind: model.EvidenceDifferentialTest, Status: model.StatusReproduced, BaseCheckID: "check-1", CheckID: "check-2", Runner: "go_test_json", TestNames: []string{"TestRegression"}}},
		Hypotheses: []model.Hypothesis{{ID: "h1", Title: "Regression", Severity: "high", Status: "REPRODUCED", EvidenceIDs: []string{"evidence-1"}}},
	}
}

const (
	goPass = "{\"Action\":\"run\",\"Test\":\"TestRegression\"}\n{\"Action\":\"pass\",\"Test\":\"TestRegression\"}\n"
	goFail = "{\"Action\":\"run\",\"Test\":\"TestRegression\"}\n{\"Action\":\"fail\",\"Test\":\"TestRegression\"}\n"
)

func cacheRecord(status string, liveRuns int) *model.CheckCache {
	return &model.CheckCache{Status: status, Key: strings.Repeat("ab", 32), RecordedAt: time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC), RecordedRun: "run-1", RecordedCheck: "check-1", RecordedDurationMS: 1200, LiveRuns: liveRuns}
}

// A replayed baseline never supports REPRODUCED; the live confirmation of the
// same kind does, even when it was written through to the cache.
func TestLiveConfirmationSupportsReproduced(t *testing.T) {
	build := func(baseCheckID string) *model.Report {
		r := goProof(goPass, goFail)
		replayed := r.Checks[0]
		replayed.Cache = cacheRecord(model.CacheHit, 2)
		live := r.Checks[0]
		live.ID, live.Cache = "check-3", cacheRecord(model.CacheStored, 3)
		r.Checks = []model.Check{replayed, r.Checks[1], live}
		r.Evidence[0].BaseCheckID = baseCheckID
		return r
	}
	r := build("check-3")
	Finalize(r, true)
	if r.Hypotheses[0].Status != model.StatusReproduced || r.ExitCode != 1 || len(r.ReproducedIssues) != 1 {
		t.Fatalf("live confirmation: status %s exit %d", r.Hypotheses[0].Status, r.ExitCode)
	}
	r = build("check-1")
	Finalize(r, true)
	if r.Hypotheses[0].Status != model.StatusUnverified || r.ExitCode != 2 || len(r.ReproducedIssues) != 0 {
		t.Fatalf("replayed baseline: status %s exit %d", r.Hypotheses[0].Status, r.ExitCode)
	}
}

// A negative conclusion may rest on a replay only after two agreeing live runs.
func TestReplayedBaselineNegativeNeedsTwoLiveRuns(t *testing.T) {
	for _, tt := range []struct {
		liveRuns int
		status   string
		exit     int
	}{{1, model.StatusUnverified, 2}, {2, model.StatusNotReproduced, 0}, {5, model.StatusNotReproduced, 0}} {
		r := goProof(goPass, goPass)
		r.Checks[1].Status, r.Checks[1].ExitCode = "PASS", 0
		r.Checks[0].Cache = cacheRecord(model.CacheHit, tt.liveRuns)
		r.Evidence[0].Status = model.StatusNotReproduced
		r.Hypotheses[0].Status = model.StatusNotReproduced
		verified := verifyCoreEvidence(r, newLedger(r))
		if (verified["evidence-1"] == model.StatusNotReproduced) != (tt.status == model.StatusNotReproduced) {
			t.Fatalf("live_runs %d: verifier returned %v", tt.liveRuns, verified)
		}
		Finalize(r, true)
		if r.Hypotheses[0].Status != tt.status || r.ExitCode != tt.exit {
			t.Fatalf("live_runs %d: status %s exit %d, want %s %d", tt.liveRuns, r.Hypotheses[0].Status, r.ExitCode, tt.status, tt.exit)
		}
	}
}

func TestReplayedCandidateSupportsNothing(t *testing.T) {
	r := goProof(goPass, goFail)
	r.Checks[1].Cache = cacheRecord(model.CacheHit, 3)
	Finalize(r, true)
	if r.Hypotheses[0].Status != model.StatusUnverified {
		t.Fatalf("a replayed candidate check supported %s", r.Hypotheses[0].Status)
	}
}

// A stored (written-through) live baseline is not a replay.
func TestStoredBaselineIsLive(t *testing.T) {
	r := goProof(goPass, goFail)
	r.Checks[0].Cache = cacheRecord(model.CacheStored, 1)
	Finalize(r, false)
	if r.Hypotheses[0].Status != model.StatusReproduced || r.ExitCode != 1 {
		t.Fatalf("stored live baseline: status %s exit %d", r.Hypotheses[0].Status, r.ExitCode)
	}
}

// Test names and paths that report sanitizing would change select nothing,
// before and after a re-render.
func TestSecretShapedTestNamesSupportNothing(t *testing.T) {
	const name = "TestAKIA0123456789ABCDEF"
	for _, tt := range []struct {
		name string
		test string
	}{{"raw secret-shaped name", name}, {"redacted name", "Test[REDACTED]"}} {
		t.Run(tt.name, func(t *testing.T) {
			r := goProof(strings.ReplaceAll(goPass, "TestRegression", tt.test), strings.ReplaceAll(goFail, "TestRegression", tt.test))
			r.Evidence[0].TestNames = []string{tt.test}
			Finalize(r, false)
			if r.Hypotheses[0].Status != model.StatusUnverified || r.ExitCode != 0 {
				t.Fatalf("status %s exit %d", r.Hypotheses[0].Status, r.ExitCode)
			}
		})
	}
	r := jestProofReport()
	const secretPath = "src/password=hunter2.test.ts"
	r.Evidence[0].Path = secretPath
	for i := range r.Checks {
		r.Checks[i].Results = strings.ReplaceAll(r.Checks[i].Results, "src/cart.test.ts", secretPath)
	}
	Finalize(r, false)
	if r.Hypotheses[0].Status != model.StatusUnverified {
		t.Fatalf("secret-shaped path supported %s", r.Hypotheses[0].Status)
	}
}

// Until the feature verifiers merge, no v0.4 evidence kind supports anything,
// and a claim resting on one requests review.
func TestStubVerifiersSupportNothing(t *testing.T) {
	for _, tt := range []struct {
		kind, status, claim string
	}{
		{model.EvidenceDifferentialObservation, model.StatusDiverged, model.StatusDiverged},
		{model.EvidenceDifferentialFuzz, model.StatusDiverged, model.StatusDiverged},
		{model.EvidenceIntentTest, model.StatusIntentTestFailed, model.StatusIntentTestFailed},
		{model.EvidenceBaseTestDifferential, model.StatusFailsOnCandidate, model.StatusReproduced},
		{model.EvidenceImpactedTestDifferential, model.StatusFailsOnCandidate, model.StatusReproduced},
	} {
		r := goProof(goPass, goFail)
		r.IntentCriteria = []model.IntentCriterion{{ID: "AC-1", Text: "x"}}
		r.Evidence[0].Kind, r.Evidence[0].Status, r.Evidence[0].CriterionID = tt.kind, tt.status, "AC-1"
		r.Evidence[0].RepeatCheckID = "check-1"
		r.Hypotheses[0].Status, r.Hypotheses[0].CriterionID = tt.claim, "AC-1"
		Finalize(r, true)
		if r.Hypotheses[0].Status != model.StatusUnverified || r.ExitCode != 2 || len(r.Divergences) != 0 || len(r.IntentTestFailures) != 0 {
			t.Errorf("%s/%s: status %s exit %d divergences %d", tt.kind, tt.status, r.Hypotheses[0].Status, r.ExitCode, len(r.Divergences))
		}
	}
}

// The fail-closed stub finalizers turn a stage that did not run into a review
// request; explicit operator choices and empty stages do not.
func TestSectionStatusesRequestReview(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*model.Report)
		exit   int
	}{
		{"nothing requested", func(*model.Report) {}, 0},
		{"fuzz not run", func(r *model.Report) { r.Fuzz = &model.FuzzReport{Status: model.FuzzNotRun} }, 2},
		{"fuzz disabled", func(r *model.Report) { r.Fuzz = &model.FuzzReport{Status: model.FuzzDisabled} }, 0},
		{"fuzz no candidates", func(r *model.Report) { r.Fuzz = &model.FuzzReport{Status: model.FuzzNoCandidates} }, 0},
		{"base tests not run", func(r *model.Report) { r.BaseTests = &model.BaseTests{Status: model.BaseTestsNotRun} }, 2},
		{"base tests no candidates", func(r *model.Report) { r.BaseTests = &model.BaseTests{Status: model.BaseTestsNoCandidates} }, 0},
		{"mutation not run", func(r *model.Report) { r.Mutation = &model.Mutation{Status: model.MutationNotRun} }, 2},
		{"mutation incomplete", func(r *model.Report) { r.Mutation = &model.Mutation{Status: model.MutationIncomplete} }, 2},
		{"mutation no candidates", func(r *model.Report) { r.Mutation = &model.Mutation{Status: model.MutationNoCandidates} }, 0},
		{"impact unavailable", func(r *model.Report) { r.Impact = &model.Impact{Status: model.ImpactUnavailable} }, 0},
		{"impacted tests not run", func(r *model.Report) {
			r.Impact = &model.Impact{Status: model.ImpactUnavailable, TestsStatus: model.ImpactTestsNotRun}
		}, 2},
		{"prepare failed (cli sets 4)", func(r *model.Report) { r.Prepare = &model.Prepare{Status: model.PrepareFailed} }, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &model.Report{}
			tt.mutate(r)
			Finalize(r, true)
			if r.ExitCode != tt.exit {
				t.Fatalf("exit %d, want %d", r.ExitCode, tt.exit)
			}
			Finalize(r, false)
			if r.ExitCode != 0 {
				t.Fatalf("exit %d without --ci", r.ExitCode)
			}
		})
	}
}

// Without verifyMutation, no SURVIVED or KILLED mutant survives Finalize.
func TestMutationStubDowngradesUnverifiedMutants(t *testing.T) {
	r := &model.Report{Mutation: &model.Mutation{
		Status: model.MutationRan,
		Mutants: []model.Mutant{
			{ID: "mutant-1", Status: model.MutantSurvived, CheckID: "mutation-check-2", ControlCheckID: "mutation-check-1", TestsRun: 3},
			{ID: "mutant-2", Status: model.MutantKilled, FailedTests: []string{"TestA"}},
			{ID: "mutant-3", Status: model.MutantInvalid},
			{ID: "mutant-4", Status: model.MutantTimeout},
			{ID: "mutant-5", Status: "APPROVED"},
		},
		Survived: 1, Killed: 1,
	}}
	Finalize(r, true)
	m := r.Mutation
	if m.Status != model.MutationIncomplete || m.Survived != 0 || m.Killed != 0 || m.Inconclusive != 3 || m.Invalid != 1 || m.TimedOut != 1 || r.ExitCode != 2 {
		t.Fatalf("mutation after Finalize: %+v exit %d", m, r.ExitCode)
	}
	for _, mu := range m.Mutants[:2] {
		if mu.Status != model.MutantInconclusive || mu.Reason == "" {
			t.Fatalf("unverified mutant kept %+v", mu)
		}
	}
	first, _ := json.Marshal(r)
	Finalize(r, true)
	second, _ := json.Marshal(r)
	if string(first) != string(second) {
		t.Fatal("mutation finalization is not idempotent")
	}
	// A verified status is kept.
	r = &model.Report{Mutation: &model.Mutation{Status: model.MutationRan, Mutants: []model.Mutant{{ID: "mutant-1", Status: model.MutantSurvived}}}}
	if finalizeMutation(r, map[string]string{"mutant-1": model.MutantSurvived}) || r.Mutation.Survived != 1 || r.Mutation.Status != model.MutationRan {
		t.Fatalf("verified survivor downgraded: %+v", r.Mutation)
	}
}
