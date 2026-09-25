package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/gvinsot/SwiftProof/app/internal/model"
)

// divergenceFixture is a report whose evidence the tests mark verified by hand:
// the F1 and F2 verifiers are stubs in F0.
func divergenceFixture() *model.Report {
	r := &model.Report{
		Change: model.Change{Files: []model.ChangedFile{
			{Path: "calc/calc.go", Status: "M"},
			{Path: "calc/gone.go", Status: "D"},
			{Path: "calc/new.go", Status: "A"},
		}},
		Evidence: []model.Evidence{
			{ID: "evidence-1", Kind: model.EvidenceDifferentialFuzz, Status: model.StatusDiverged, Path: "calc/swiftproof_fuzz_test.go", TestNames: []string{"TestSwiftProofFuzz"}},
			{ID: "evidence-2", Kind: model.EvidenceDifferentialObservation, Status: model.StatusDiverged, Path: "calc/obs_test.go", TestNames: []string{"TestDiscount"}},
			{ID: "evidence-3", Kind: model.EvidenceDifferentialObservation, Status: model.StatusNotDiverged, Path: "calc/eq_test.go", TestNames: []string{"TestEqual"}},
			{ID: "evidence-4", Kind: model.EvidenceDifferentialObservation, Status: model.StatusDiverged, Path: "calc/other_test.go", TestNames: []string{"TestOther"}},
			{ID: "evidence-5", Kind: model.EvidenceDifferentialObservation, Status: model.StatusDiverged, TestNames: []string{"TestNoPath"}},
		},
	}
	for i := 1; i <= 8; i++ {
		r.Checks = append(r.Checks, model.Check{ID: fmt.Sprintf("check-%d", i), Status: "PASS"})
	}
	return r
}

func verifiedLedger(r *model.Report, ids ...string) *ledger {
	l := newLedger(r)
	for _, id := range ids {
		if e, ok := l.item(id); ok {
			l.verified[id] = e.Status
		}
	}
	return l
}

func divergedRow(key, base, candidate string) model.Observation {
	return model.Observation{Test: "TestDiscount", Key: key, Status: model.ObservationDiverged, Base: base, Candidate: candidate, BaseRecorded: true, CandidateRecorded: true}
}

func observationEntry(id string) model.Divergence {
	return model.Divergence{
		EvidenceID: id, Kind: model.EvidenceDifferentialObservation,
		TestPath: "calc/obs_test.go", TestNames: []string{"TestDiscount"},
		CheckIDs:     []string{"check-1", "check-2", "check-3"},
		Observations: []model.Observation{divergedRow("Discount(5,33)", "4", "3")},
	}
}

func fuzzEntry(id string) model.Divergence {
	return model.Divergence{
		EvidenceID: id, Kind: model.EvidenceDifferentialFuzz,
		Path: "calc/calc.go", Line: 21, Symbol: "Discount", AnchorSource: anchorChangedFunction,
		TestPath: "calc/swiftproof_fuzz_test.go", TestNames: []string{"TestSwiftProofFuzz"},
		CheckIDs:     []string{"check-4", "check-5", "check-6", "check-7"},
		Observations: []model.Observation{divergedRow("Discount(1000)", "900", "901")},
	}
}

func TestSelectDivergencesKeepsOnlyValidatedEntries(t *testing.T) {
	r := divergenceFixture()
	l := verifiedLedger(r, "evidence-1", "evidence-2", "evidence-3", "evidence-5")
	tooFewObservationChecks := observationEntry("evidence-2")
	tooFewObservationChecks.CheckIDs = tooFewObservationChecks.CheckIDs[:2]
	tooFewFuzzChecks := fuzzEntry("evidence-1")
	tooFewFuzzChecks.CheckIDs = tooFewFuzzChecks.CheckIDs[:3]
	unresolvedCheck := observationEntry("evidence-2")
	unresolvedCheck.CheckIDs = []string{"check-1", "check-2", "check-99"}
	kindMismatch := observationEntry("evidence-1")
	notDiverged := observationEntry("evidence-3")
	unverified := observationEntry("evidence-4")
	missing := observationEntry("evidence-9")
	noRows := observationEntry("evidence-2")
	noRows.Observations = []model.Observation{{Test: "TestDiscount", Key: "k", Status: model.ObservationEqual, Base: "1", Candidate: "1"}}
	otherKind := observationEntry("evidence-2")
	otherKind.Kind = model.EvidenceDifferentialTest
	// Entries the schema would reject: no test path even after the fallback to
	// the evidence record, an empty test name, rows without a test or a key.
	noTestPath := observationEntry("evidence-5")
	noTestPath.TestPath = ""
	emptyName := observationEntry("evidence-2")
	emptyName.TestNames = []string{"TestDiscount", ""}
	emptyRowTest := observationEntry("evidence-2")
	emptyRowTest.Observations[0].Test = ""
	emptyRowKey := observationEntry("evidence-2")
	emptyRowKey.Observations[0].Key = ""
	for name, d := range map[string]model.Divergence{
		"too few observation checks": tooFewObservationChecks,
		"too few fuzz checks":        tooFewFuzzChecks,
		"unresolved check":           unresolvedCheck,
		"kind mismatch":              kindMismatch,
		"verified NOT_DIVERGED":      notDiverged,
		"unverified evidence":        unverified,
		"missing evidence":           missing,
		"no DIVERGED row":            noRows,
		"not a divergence kind":      otherKind,
		"no test path":               noTestPath,
		"empty test name":            emptyName,
		"row without a test":         emptyRowTest,
		"row without a key":          emptyRowKey,
	} {
		if got := selectDivergences(r, l, []model.Divergence{d}); len(got) != 0 {
			t.Errorf("%s: kept %+v", name, got)
		}
	}
	// A duplicated check ID in the report resolves nowhere.
	r.Checks = append(r.Checks, model.Check{ID: "check-3"})
	if got := selectDivergences(r, verifiedLedger(r, "evidence-2"), []model.Divergence{observationEntry("evidence-2")}); len(got) != 0 {
		t.Errorf("duplicated check kept %+v", got)
	}
	// Rows without a test or key are dropped one by one; the entry keeps the rest.
	r = divergenceFixture()
	mixed := observationEntry("evidence-2")
	mixed.Observations = append(mixed.Observations, model.Observation{Key: "k", Status: model.ObservationDiverged}, model.Observation{Test: "TestDiscount", Status: model.ObservationDiverged})
	got := selectDivergences(r, verifiedLedger(r, "evidence-2"), []model.Divergence{mixed})
	if len(got) != 1 || len(got[0].Observations) != 1 || got[0].Observations[0].Key != "Discount(5,33)" {
		t.Errorf("rows without a test or key were kept: %+v", got)
	}
}

// concludeFresh resets the derived fields as Finalize does before conclude.
func concludeFresh(r *model.Report, l *ledger, ci bool, feed func(*model.Report, *ledger) []model.Divergence) {
	r.Version, r.ExitCode = 1, 0
	r.ReproducedIssues, r.Divergences, r.IntentTestFailures, r.ReviewTargets = nil, nil, nil, nil
	conclude(r, l, ci, feed)
}

func TestSelectDivergencesOrderRowsAndCaps(t *testing.T) {
	r := divergenceFixture()
	l := verifiedLedger(r, "evidence-1", "evidence-2", "evidence-4")
	obs := observationEntry("evidence-2")
	obs.Observations = nil
	for i := 0; i < 40; i++ {
		obs.Observations = append(obs.Observations, divergedRow(fmt.Sprintf("k%02d", i), "a", "b"))
		obs.Observations = append(obs.Observations, model.Observation{Test: "TestDiscount", Key: fmt.Sprintf("u%02d", i), Status: model.ObservationUnstable})
	}
	duplicate := observationEntry("evidence-2")
	duplicate.Observations = []model.Observation{divergedRow("duplicate", "x", "y")}
	other := observationEntry("evidence-4")
	other.TestNames, other.TestPath, other.CheckIDs = nil, "", []string{"check-1", "check-2", "check-3", "check-8"}
	// Feed order: observations first, then fuzz, as buildDivergences does.
	got := selectDivergences(r, l, []model.Divergence{other, obs, duplicate, fuzzEntry("evidence-1")})
	if len(got) != 3 || got[0].EvidenceID != "evidence-1" || got[1].EvidenceID != "evidence-2" || got[2].EvidenceID != "evidence-4" {
		t.Fatalf("entries are not in evidence order, one per evidence: %+v", got)
	}
	if n := len(got[1].Observations); n != maxDivergenceRows {
		t.Fatalf("kept %d rows, want %d", n, maxDivergenceRows)
	}
	for i, o := range got[1].Observations {
		if o.Status != model.ObservationDiverged || o.Key != fmt.Sprintf("k%02d", i) {
			t.Fatalf("row %d is %+v", i, o)
		}
	}
	for _, d := range got {
		if d.Note != model.DivergenceNote || d.HypothesisIDs == nil || d.TestNames == nil || d.CheckIDs == nil || d.Observations == nil {
			t.Fatalf("entry not normalized: %+v", d)
		}
	}
	if got[2].TestPath != "calc/other_test.go" || len(got[2].TestNames) != 1 || got[2].TestNames[0] != "TestOther" {
		t.Fatalf("test path and names do not fall back to the evidence record: %+v", got[2])
	}
	data, _ := json.Marshal(got)
	if strings.Contains(string(data), "null") {
		t.Fatalf("a divergence serializes null: %s", data)
	}
}

func TestSelectDivergencesAnchorsAndCitingHypotheses(t *testing.T) {
	r := divergenceFixture()
	r.Hypotheses = []model.Hypothesis{
		{ID: "h-deleted", Status: model.StatusDiverged, EvidenceIDs: []string{"evidence-2"}, Path: "calc/gone.go", Line: 3},
		{ID: "h-unchanged", Status: model.StatusDiverged, EvidenceIDs: []string{"evidence-2"}, Path: "calc/untouched.go", Line: 4},
		{ID: "h-unverified", Status: model.StatusUnverified, EvidenceIDs: []string{"evidence-2"}, Path: "calc/calc.go", Line: 5},
		{ID: "h-other", Status: model.StatusDiverged, EvidenceIDs: []string{"evidence-4"}, Path: "calc/calc.go", Line: 6},
		{ID: "h-b", Status: model.StatusDiverged, EvidenceIDs: []string{"evidence-9", "evidence-2"}, Path: "calc/calc.go", Line: 12},
		{ID: "h-a", Status: model.StatusDiverged, EvidenceIDs: []string{"evidence-2"}, Path: "calc/new.go", Line: 1},
		{ID: "h-fuzz", Status: model.StatusDiverged, EvidenceIDs: []string{"evidence-1"}, Path: "calc/new.go", Line: 9},
	}
	l := verifiedLedger(r, "evidence-1", "evidence-2", "evidence-4")
	preset := observationEntry("evidence-2")
	// An observation feed cannot anchor itself: only a citing hypothesis does.
	preset.Path, preset.Line, preset.Symbol, preset.AnchorSource = "calc/calc.go", 99, "Discount", anchorChangedFunction
	unanchored := observationEntry("evidence-4")
	unanchored.CheckIDs = []string{"check-1", "check-2", "check-8"}
	r.Hypotheses[3].Path = "calc/gone.go"
	got := linkDivergences(r, selectDivergences(r, l, []model.Divergence{preset, unanchored, fuzzEntry("evidence-1")}))
	if len(got) != 3 {
		t.Fatalf("entries %+v", got)
	}
	fuzz, obs, other := got[0], got[1], got[2]
	if fuzz.Path != "calc/calc.go" || fuzz.Line != 21 || fuzz.Symbol != "Discount" || fuzz.AnchorSource != anchorChangedFunction || strings.Join(fuzz.HypothesisIDs, ",") != "h-fuzz" {
		t.Fatalf("fuzz entry lost its changed-function anchor: %+v", fuzz)
	}
	if obs.Path != "calc/calc.go" || obs.Line != 12 || obs.Symbol != "" || obs.AnchorSource != anchorHypothesis {
		t.Fatalf("observation not anchored at the lowest-index DIVERGED hypothesis naming a changed file: %+v", obs)
	}
	if strings.Join(obs.HypothesisIDs, ",") != "h-a,h-b,h-deleted,h-unchanged" {
		t.Fatalf("citing hypotheses %v", obs.HypothesisIDs)
	}
	if other.Path != "" || other.Line != 0 || other.AnchorSource != "" || strings.Join(other.HypothesisIDs, ",") != "h-other" {
		t.Fatalf("an entry cited only from a deleted file must stay unanchored: %+v", other)
	}
	// A fuzz anchor must also name a changed, non-deleted file.
	for _, path := range []string{"calc/gone.go", "calc/untouched.go"} {
		d := fuzzEntry("evidence-1")
		d.Path = path
		got := selectDivergences(r, l, []model.Divergence{d})
		if len(got) != 1 || got[0].Path != "" || got[0].Line != 0 || got[0].Symbol != "" || got[0].AnchorSource != "" {
			t.Fatalf("fuzz entry anchored at %s: %+v", path, got)
		}
	}
	// selectDivergences alone cites no hypothesis: linking happens once the
	// statuses are final.
	if got := selectDivergences(r, l, []model.Divergence{observationEntry("evidence-2")}); len(got) != 1 || len(got[0].HypothesisIDs) != 0 || got[0].Path != "" {
		t.Fatalf("selectDivergences linked hypotheses: %+v", got)
	}
}

// A DIVERGED claim is accepted only when an entry it cites is listed in
// Behavior Divergences, so the Investigation Summary and that section agree.
func TestDivergedClaimNeedsAListedDivergence(t *testing.T) {
	for _, tt := range []struct {
		name string
		feed func(*model.Report, *ledger) []model.Divergence
		want string
	}{
		{"listed", func(r *model.Report, l *ledger) []model.Divergence {
			return selectDivergences(r, l, []model.Divergence{observationEntry("evidence-2")})
		}, model.StatusDiverged},
		{"feed without an entry", noDivergences, model.StatusUnverified},
		{"entry rejected by selection", func(r *model.Report, l *ledger) []model.Divergence {
			d := observationEntry("evidence-2")
			d.CheckIDs = d.CheckIDs[:2]
			return selectDivergences(r, l, []model.Divergence{d})
		}, model.StatusUnverified},
		{"only another entry listed", func(r *model.Report, l *ledger) []model.Divergence {
			return selectDivergences(r, l, []model.Divergence{fuzzEntry("evidence-1")})
		}, model.StatusUnverified},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := divergenceFixture()
			r.Hypotheses = []model.Hypothesis{{ID: "h1", Title: "Discount changed", Severity: "high", Status: "DIVERGED", EvidenceIDs: []string{"evidence-2"}, Path: "calc/calc.go", Line: 12}}
			concludeFresh(r, verifiedLedger(r, "evidence-1", "evidence-2"), true, tt.feed)
			if got := r.Hypotheses[0].Status; got != tt.want {
				t.Fatalf("status %s, want %s", got, tt.want)
			}
			cited := false
			for _, d := range r.Divergences {
				cited = cited || strings.Join(d.HypothesisIDs, ",") == "h1"
			}
			if cited != (tt.want == model.StatusDiverged) || r.ExitCode != 2 {
				t.Fatalf("divergences %+v exit %d", r.Divergences, r.ExitCode)
			}
		})
	}
}

// A divergence requests review and never produces exit 1, whatever the severity
// of the hypotheses that cite it.
func TestDivergencesRequestReviewAndNeverExitOne(t *testing.T) {
	for _, ci := range []bool{false, true} {
		r := divergenceFixture()
		r.Hypotheses = []model.Hypothesis{{ID: "h1", Title: "Discount rounding changed", Severity: "critical", Status: "DIVERGED", EvidenceIDs: []string{"evidence-2"}, Path: "calc/calc.go", Line: 12}}
		feed := func(r *model.Report, l *ledger) []model.Divergence {
			return selectDivergences(r, l, []model.Divergence{observationEntry("evidence-2"), fuzzEntry("evidence-1")})
		}
		l := verifiedLedger(r, "evidence-1", "evidence-2")
		concludeFresh(r, l, ci, feed)
		want := 0
		if ci {
			want = 2
		}
		if r.ExitCode != want || len(r.Divergences) != 2 || len(r.ReproducedIssues) != 0 || r.Hypotheses[0].Status != model.StatusDiverged {
			t.Fatalf("ci=%v: exit %d, divergences %d, status %s", ci, r.ExitCode, len(r.Divergences), r.Hypotheses[0].Status)
		}
		// An uncited divergence alone also requests review under --ci.
		r.Hypotheses = nil
		concludeFresh(r, verifiedLedger(r, "evidence-1", "evidence-2"), ci, feed)
		if r.ExitCode != want || len(r.Divergences) != 2 {
			t.Fatalf("ci=%v uncited: exit %d", ci, r.ExitCode)
		}
		first, _ := json.Marshal(r)
		concludeFresh(r, verifiedLedger(r, "evidence-1", "evidence-2"), ci, feed)
		second, _ := json.Marshal(r)
		if string(first) != string(second) {
			t.Fatal("divergence selection is not idempotent")
		}
	}
}

func TestWriteDivergencesEmptyTexts(t *testing.T) {
	md := string(Markdown(&model.Report{}))
	if got := strings.TrimSpace(section(t, md, "## Behavior Divergences")); got != noExperimentText {
		t.Fatalf("empty report: %q", got)
	}
	render := func(r *model.Report, verified map[string]string) string {
		var b bytes.Buffer
		writeDivergences(&b, r, verified)
		return strings.TrimSpace(strings.TrimPrefix(b.String(), "\n## Behavior Divergences\n"))
	}
	for _, kind := range []string{model.EvidenceDifferentialObservation, model.EvidenceDifferentialFuzz} {
		r := &model.Report{Evidence: []model.Evidence{{ID: "evidence-1", Kind: kind, Status: model.StatusNotDiverged}}}
		// Equal values are claimed only for an accepted NOT_DIVERGED status.
		if got := render(r, map[string]string{"evidence-1": model.StatusNotDiverged}); got != noDivergenceText {
			t.Fatalf("%s with an accepted NOT_DIVERGED: %q", kind, got)
		}
		unvalidated := fmt.Sprintf(unvalidatedText, 1, 1)
		if got := render(r, nil); got != unvalidated {
			t.Fatalf("%s whose stored NOT_DIVERGED was not accepted: %q", kind, got)
		}
		// Markdown re-derives the statuses: the F0 stub verifiers accept none.
		if got := strings.TrimSpace(section(t, string(Markdown(r)), "## Behavior Divergences")); got != unvalidated {
			t.Fatalf("%s rendered through Markdown: %q", kind, got)
		}
	}
	// One accepted and two unaccepted records: nothing is said about equal values.
	r := &model.Report{Evidence: []model.Evidence{
		{ID: "evidence-1", Kind: model.EvidenceDifferentialObservation, Status: model.StatusNotDiverged},
		{ID: "evidence-2", Kind: model.EvidenceDifferentialFuzz, Status: model.StatusUnverified},
		{ID: "evidence-3", Kind: model.EvidenceDifferentialObservation, Status: model.StatusDiverged},
		{ID: "evidence-4", Kind: model.EvidenceDifferentialTest, Status: model.StatusNotReproduced},
	}}
	if got := render(r, map[string]string{"evidence-1": model.StatusNotDiverged, "evidence-4": model.StatusNotReproduced}); got != fmt.Sprintf(unvalidatedText, 2, 3) {
		t.Fatalf("mixed records: %q", got)
	}
	// Other evidence kinds are not experiments of this section.
	r = &model.Report{Evidence: []model.Evidence{{ID: "evidence-1", Kind: model.EvidenceDifferentialTest, Status: model.StatusNotReproduced}}}
	if got := strings.TrimSpace(section(t, string(Markdown(r)), "## Behavior Divergences")); got != noExperimentText {
		t.Fatalf("differential_test only: %q", got)
	}
}

func TestWriteDivergencesEntries(t *testing.T) {
	obs := observationEntry("evidence-2")
	obs.Path, obs.Line, obs.AnchorSource, obs.HypothesisIDs = "calc/calc.go", 12, anchorHypothesis, []string{"h1", "h2"}
	obs.Observations = []model.Observation{
		divergedRow("Discount(5,33)", "4", "3"),
		{Test: "TestDiscount", Key: "Missing()", Status: model.ObservationDiverged, Base: "", Candidate: "7", CandidateRecorded: true},
		{Test: "TestDiscount", Key: "Empty()", Status: model.ObservationDiverged, Base: "", Candidate: "x", BaseRecorded: true, CandidateRecorded: true},
		{Test: "TestDiscount", Key: "Long()", Status: model.ObservationDiverged, Base: "aaaa", Candidate: "bbbb", BaseRecorded: true, CandidateRecorded: true, Truncated: true},
	}
	many := fuzzEntry("evidence-1")
	many.HypothesisIDs = nil
	many.Observations = nil
	for i := 0; i < 25; i++ {
		many.Observations = append(many.Observations, divergedRow(fmt.Sprintf("Discount(%d)", i), "1", "2"))
	}
	loose := observationEntry("evidence-4")
	loose.TestNames = []string{"TestA", "TestB"}
	r := &model.Report{Divergences: []model.Divergence{many, obs, loose}}
	body := section(t, string(Markdown(r)), "## Behavior Divergences")
	for _, want := range []string{
		"- **evidence-1** differential\\_fuzz — calc/calc.go:21 (changed function); test calc/swiftproof\\_fuzz\\_test.go (TestSwiftProofFuzz); hypotheses: none\n",
		"- **evidence-2** differential\\_observation — calc/calc.go:12 (model-chosen location); test calc/obs\\_test.go (TestDiscount); hypotheses: h1, h2\n",
		"- **evidence-4** differential\\_observation — no anchor; test calc/obs\\_test.go (TestA, TestB); hypotheses: none\n",
		"  - Discount\\(5,33\\): baseline 4; candidate 3\n",
		"  - Missing\\(\\): baseline (not recorded); candidate 7\n",
		"  - Empty\\(\\): baseline (empty); candidate x\n",
		"  - Long\\(\\): baseline aaaa; candidate bbbb (values cut for display)\n",
		"  - Discount\\(19\\): baseline 1; candidate 2\n",
		"  - … 5 more in confidence-report.json\n",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in:\n%s", want, body)
		}
	}
	if strings.Contains(body, "Discount\\(20\\)") {
		t.Error("more than 20 rows rendered for one divergence")
	}
	if n := strings.Count(body, inline(model.DivergenceNote)); n != 1 {
		t.Errorf("note rendered %d times, want once at the end", n)
	}
	if !strings.HasSuffix(strings.TrimSpace(body), inline(model.DivergenceNote)) {
		t.Errorf("note is not the last line:\n%s", body)
	}
}

func TestWriteDivergencesEscapesHostileStrings(t *testing.T) {
	const (
		hostileKey   = "k\n# Injected Heading"
		hostileValue = "![x](https://evil.test/i.png) <script>alert(1)</script> `code` [link](http://x) | *b* _i_"
		hostilePath  = "calc/[x](y).go\n## Fake"
		hostileTest  = "Test<img src=x>"
	)
	d := observationEntry("evidence-2")
	d.Path, d.AnchorSource, d.TestPath = hostilePath, anchorHypothesis, hostilePath
	d.TestNames, d.HypothesisIDs = []string{hostileTest}, []string{"h1)[z](http://evil"}
	d.EvidenceID = "evidence-2**bold**"
	d.Observations = []model.Observation{{Test: hostileTest, Key: hostileKey, Status: model.ObservationDiverged, Base: hostileValue, Candidate: hostileValue + "!", BaseRecorded: true, CandidateRecorded: true}}
	md := string(Markdown(&model.Report{Divergences: []model.Divergence{d}}))
	if stray := strayHeadings(md); len(stray) > 0 {
		t.Fatalf("hostile divergence strings produced headings: %q", stray)
	}
	for _, raw := range []string{"<script>", "<img", "![x]", "](https", "`code`", "[link]", "\n# Injected", "\n## Fake", "**bold**"} {
		if strings.Contains(md, raw) {
			t.Errorf("unescaped %q reached the report", raw)
		}
	}
	body := section(t, md, "## Behavior Divergences")
	for _, want := range []string{inline(hostileKey), inline(hostileValue), inline(hostilePath), inline(hostileTest)} {
		if !strings.Contains(body, want) {
			t.Errorf("escaped form %q missing", want)
		}
	}
}

func TestEvidenceCheckLine(t *testing.T) {
	for _, tt := range []struct {
		e    model.Evidence
		want string
	}{
		{model.Evidence{Kind: model.EvidenceSourceObservation}, ""},
		{model.Evidence{Kind: model.EvidenceDifferentialTest, CheckID: "check-2", BaseCheckID: "check-1"}, "Candidate check: check-2; baseline check: check-1"},
		{model.Evidence{Kind: model.EvidenceIntentTest, CheckID: "check-3"}, "Candidate check: check-3 (candidate-only; no baseline control)"},
		{model.Evidence{Kind: model.EvidenceBaseTestDifferential, CheckID: "check-5", BaseCheckID: "check-4"}, "Hybrid-tree check: check-5; baseline check: check-4"},
		{model.Evidence{Kind: model.EvidenceDifferentialObservation, CheckID: "check-2", BaseCheckID: "check-1", RepeatCheckID: "check-6"}, "Candidate check: check-2; baseline check: check-1; baseline repeat: check-6"},
		{model.Evidence{Kind: model.EvidenceImpactedTestDifferential, CheckID: "check_8", BaseCheckID: "check_7"}, "Candidate check: check\\_8; baseline check: check\\_7"},
	} {
		if got := evidenceCheckLine(tt.e); got != tt.want {
			t.Errorf("%s: %q, want %q", tt.e.Kind, got, tt.want)
		}
	}
	md := string(Markdown(&model.Report{Evidence: []model.Evidence{{ID: "evidence-1", Kind: model.EvidenceIntentTest, Status: model.StatusIntentTestFailed, CheckID: "check-3"}}}))
	if !strings.Contains(section(t, md, "## Recorded Evidence"), "\n  Candidate check: check-3 (candidate-only; no baseline control)\n") {
		t.Fatalf("evidence check line not rendered:\n%s", md)
	}
}

// The F0 headings keep the §1.10.4 order whatever optional sections exist.
func TestMarkdownSectionOrder(t *testing.T) {
	r := proofReport()
	r.Intent = "Discounts apply once."
	r.IntentCriteria = []model.IntentCriterion{{ID: "AC-1", Text: "x", Line: 1}}
	r.Prepare = &model.Prepare{Status: model.PrepareNotRun}
	r.BaseTests = &model.BaseTests{Status: model.BaseTestsNoCandidates}
	r.Mutation = &model.Mutation{Status: model.MutationNoCandidates}
	r.Fuzz = &model.FuzzReport{Status: model.FuzzDisabled}
	r.Impact = &model.Impact{Status: model.ImpactUnavailable}
	r.Artifacts = []model.Artifact{{Path: "artifacts/check-1.log", Kind: "check_output"}}
	Finalize(r, true)
	md := string(Markdown(r))
	order := []string{
		"# Change Confidence Report", "## Change Summary", "## Automated Checks", "## Investigation Summary",
		"## Reproduced Issues", "## Behavior Divergences", "## Unverified Areas", "## Suggested Human Review",
		"## Review Surface", "## Changed-line Execution", "## Recorded Evidence", "## Artifacts",
	}
	last := -1
	for _, h := range order {
		i := strings.Index(md, "\n"+h+"\n")
		if h == order[0] {
			i = strings.Index(md, h+"\n")
		}
		if i <= last {
			t.Fatalf("%q at %d, after previous section at %d:\n%s", h, i, last, md)
		}
		last = i
	}
	if stray := strayHeadings(md); len(stray) > 0 {
		t.Fatalf("unexpected headings %q", stray)
	}
}
