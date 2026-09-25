package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/gvinsot/SwiftProof/app/internal/coverage"
	"github.com/gvinsot/SwiftProof/app/internal/model"
)

func proofReport() *model.Report {
	return &model.Report{
		Checks:     []model.Check{{ID: "base", Kind: "generated_test_base", Status: "PASS", ExitCode: 0, Command: []string{"go", "test", "-json", "-count=1", "-run", "^TestRegression$", "."}, Output: "{\"Action\":\"run\",\"Test\":\"TestRegression\"}\n{\"Action\":\"pass\",\"Test\":\"TestRegression\"}\n"}, {ID: "candidate", Kind: "generated_test_candidate", Status: "FAIL", ExitCode: 1, Command: []string{"go", "test", "-json", "-count=1", "-run", "^TestRegression$", "."}, Output: "{\"Action\":\"run\",\"Test\":\"TestRegression\"}\n{\"Action\":\"fail\",\"Test\":\"TestRegression\"}\n"}},
		Evidence:   []model.Evidence{{ID: "experiment", Kind: "differential_test", Status: "REPRODUCED", BaseCheckID: "base", CheckID: "candidate", Runner: "go_test_json", TestNames: []string{"TestRegression"}}},
		Hypotheses: []model.Hypothesis{{ID: "h1", Title: "Regression", Severity: "high", Status: "REPRODUCED", EvidenceIDs: []string{"experiment"}}},
	}
}

func TestFinalizeRequiresDifferentialProof(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*model.Report)
		status string
		exit   int
	}{
		{"valid", func(*model.Report) {}, "REPRODUCED", 1},
		{"invented ID", func(r *model.Report) { r.Hypotheses[0].EvidenceIDs = []string{"invented"} }, "UNVERIFIED", 2},
		{"no evidence", func(r *model.Report) { r.Hypotheses[0].EvidenceIDs = nil }, "UNVERIFIED", 2},
		{"baseline fails", func(r *model.Report) { r.Checks[0].Status = "FAIL"; r.Checks[0].ExitCode = 1 }, "UNVERIFIED", 2},
		{"candidate timeout", func(r *model.Report) { r.Checks[1].Status = "TIMEOUT" }, "UNVERIFIED", 2},
		{"different commands", func(r *model.Report) { r.Checks[0].Command = []string{"true"} }, "UNVERIFIED", 2},
		{"missing check", func(r *model.Report) { r.Checks = r.Checks[:1] }, "UNVERIFIED", 2},
		{"ordinary test", func(r *model.Report) { r.Evidence[0].Kind = "existing_test" }, "UNVERIFIED", 2},
		{"duplicate evidence", func(r *model.Report) { r.Evidence = append(r.Evidence, r.Evidence[0]) }, "UNVERIFIED", 2},
		{"duplicate check", func(r *model.Report) { r.Checks = append(r.Checks, r.Checks[0]) }, "UNVERIFIED", 2},
		{"container error", func(r *model.Report) { r.Checks[1].ExitCode = 125 }, "UNVERIFIED", 2},
		{"missing test names", func(r *model.Report) { r.Evidence[0].TestNames = nil }, "UNVERIFIED", 2},
		{"unsupported runner", func(r *model.Report) { r.Evidence[0].Runner = "generic" }, "UNVERIFIED", 2},
		{"unrelated failure", func(r *model.Report) {
			r.Checks[1].Output = strings.ReplaceAll(r.Checks[1].Output, "TestRegression", "TestOther")
		}, "UNVERIFIED", 2},
		{"baseline test not run", func(r *model.Report) { r.Checks[0].Output = "ok [no tests to run]" }, "UNVERIFIED", 2},
		{"truncated transcript", func(r *model.Report) { r.Checks[1].Truncated = true }, "UNVERIFIED", 2},
		{"invented negative proof", func(r *model.Report) { r.Hypotheses[0].Status = "NOT_REPRODUCED" }, "UNVERIFIED", 2},
		{"invented dismissal", func(r *model.Report) { r.Hypotheses[0].Status = "DISMISSED"; r.Hypotheses[0].Rationale = "looks fine" }, "UNVERIFIED", 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := proofReport()
			tt.mutate(r)
			Finalize(r, true)
			if r.Hypotheses[0].Status != tt.status || r.ExitCode != tt.exit {
				t.Fatalf("got status %s exit %d", r.Hypotheses[0].Status, r.ExitCode)
			}
			if (len(r.ReproducedIssues) > 0) != (tt.status == "REPRODUCED") {
				t.Fatal("reproduced list disagrees")
			}
		})
	}
}

func TestNegativeExperimentNeedsPassingBaselineAndCandidate(t *testing.T) {
	r := proofReport()
	r.Hypotheses[0].Status = "NOT_REPRODUCED"
	r.Evidence[0].Status = "NOT_REPRODUCED"
	r.Checks[1].Status = "PASS"
	r.Checks[1].ExitCode = 0
	r.Checks[1].Output = r.Checks[0].Output
	Finalize(r, true)
	if r.Hypotheses[0].Status != "NOT_REPRODUCED" || r.ExitCode != 0 {
		t.Fatalf("negative experiment: %+v", r)
	}
}

func TestDismissalRequiresActualSourceObservation(t *testing.T) {
	r := &model.Report{
		Evidence:   []model.Evidence{{ID: "source", Kind: "source_observation", Status: "OBSERVED", Output: "if amount < 0 { return err }"}},
		Hypotheses: []model.Hypothesis{{ID: "h", Title: "Negative input", Severity: "medium", Status: "DISMISSED", Rationale: "The source explicitly checks the input before use.", EvidenceIDs: []string{"source"}}},
	}
	Finalize(r, true)
	if r.Hypotheses[0].Status != "DISMISSED" {
		t.Fatalf("source-backed dismissal rejected: %s", r.Hypotheses[0].Status)
	}
	r.Evidence[0].Output = ""
	Finalize(r, true)
	if r.Hypotheses[0].Status != "UNVERIFIED" {
		t.Fatal("empty observation accepted")
	}
}

func TestSurfaceDeduplicatesCoordinatesAndPrioritizesRisk(t *testing.T) {
	r := &model.Report{Change: model.Change{Files: []model.ChangedFile{{Path: "new.go", OldPath: "old.go", Hunks: []model.Hunk{{Lines: []model.DiffLine{{Kind: "delete", OldLine: 5}, {Kind: "add", NewLine: 5}, {Kind: "add", NewLine: 6}, {Kind: "add", NewLine: 7}}}}}}}, Signals: []model.Signal{
		{ID: "a", Path: "new.go", Line: 5, EndLine: 6, Side: "new", Severity: "low", Summary: "First"},
		{ID: "b", Path: "new.go", Line: 6, EndLine: 7, Side: "new", Severity: "high", Summary: "Overlap"},
		{ID: "c", Path: "old.go", Line: 5, Side: "old", Severity: "medium", Summary: "Deletion"},
	}}
	Finalize(r, true)
	if r.ReviewSurface.FocusedLines != 4 || r.ReviewSurface.ChangedLines != 4 {
		t.Fatalf("bad surface %+v", r.ReviewSurface)
	}
	if len(r.ReviewTargets) != 2 || r.ReviewTargets[0].Severity != "high" || r.ReviewTargets[0].StartLine != 5 || r.ReviewTargets[0].EndLine != 7 {
		t.Fatalf("bad targets %+v", r.ReviewTargets)
	}
	before, _ := json.Marshal(r)
	Finalize(r, true)
	after, _ := json.Marshal(r)
	if string(before) != string(after) {
		t.Fatal("Finalize is not idempotent")
	}
}

func TestWriteEscapesMarkdownAndHidesSensitiveDiff(t *testing.T) {
	r := &model.Report{Intent: "![tracking](https://evil.test/image) <script>evil</script>\n# fake", Change: model.Change{Files: []model.ChangedFile{{Path: ".env", Hunks: []model.Hunk{{Lines: []model.DiffLine{{Kind: "add", NewLine: 1, Content: "PRIVATE_VALUE=do-not-leak"}}}}}}}}
	dir := t.TempDir()
	if err := Write(dir, r, []string{"markdown", "json"}); err != nil {
		t.Fatal(err)
	}
	md, err := os.ReadFile(filepath.Join(dir, "CONFIDENCE_REPORT.md"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(md), "![tracking]") || strings.Contains(string(md), "<script>") || strings.Contains(string(md), "\n# fake") {
		t.Fatalf("unsafe markdown: %s", md)
	}
	data, err := os.ReadFile(filepath.Join(dir, "confidence-report.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "do-not-leak") {
		t.Fatal("sensitive file contents leaked")
	}
	var saved model.Report
	if err := json.Unmarshal(data, &saved); err != nil {
		t.Fatal(err)
	}
	if r.Change.Files[0].Hunks[0].Lines[0].Content != "PRIVATE_VALUE=do-not-leak" {
		t.Fatal("sanitization changed original")
	}
	if err := Write(dir, r, []string{"json"}); err != nil {
		t.Fatalf("atomic replacement failed: %v", err)
	}
}

func TestInvalidFormatDoesNotWritePartialReport(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "missing")
	if err := Write(dir, &model.Report{}, []string{"json", "bogus"}); err == nil {
		t.Fatal("expected error")
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("invalid format modified output")
	}
}

func TestBinaryOnlyDiffRequiresHumanReviewWithoutChecks(t *testing.T) {
	r := &model.Report{Change: model.Change{Files: []model.ChangedFile{{Path: "asset.bin", Binary: true}}}}
	Finalize(r, true)
	if r.ExitCode != 2 {
		t.Fatalf("binary-only diff without checks: exit %d", r.ExitCode)
	}
}

func TestEmptyCollectionsSerializeAsArrays(t *testing.T) {
	r := &model.Report{Version: 1}
	dir := t.TempDir()
	if err := Write(dir, r, []string{"json"}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "confidence-report.json"))
	if err != nil {
		t.Fatal(err)
	}
	var saved map[string]any
	if err := json.Unmarshal(data, &saved); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"linter", "checks", "hypotheses", "evidence", "reproduced_issues", "unverified", "review_targets", "artifacts", "audit"} {
		values, ok := saved[key].([]any)
		if !ok || len(values) != 0 {
			t.Errorf("%s must be an empty JSON array, got %#v", key, saved[key])
		}
	}
	change := saved["change"].(map[string]any)
	if values, ok := change["files"].([]any); !ok || len(values) != 0 {
		t.Fatalf("files must be empty array: %#v", change["files"])
	}
	if r.Checks != nil || r.Change.Files != nil {
		t.Fatal("serialization mutated caller's report")
	}
	if err := Write(dir, r, []string{"json"}); err != nil {
		t.Fatal(err)
	}
	again, err := os.ReadFile(filepath.Join(dir, "confidence-report.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != string(again) {
		t.Fatal("empty serialization is unstable")
	}
}

func BenchmarkFinalizeLargeDiff(b *testing.B) {
	r := model.Report{}
	for f := 0; f < 100; f++ {
		file := model.ChangedFile{Path: fmtPath(f)}
		h := model.Hunk{}
		for line := 1; line <= 100; line++ {
			h.Lines = append(h.Lines, model.DiffLine{Kind: "add", NewLine: line})
		}
		file.Hunks = []model.Hunk{h}
		r.Change.Files = append(r.Change.Files, file)
		r.Signals = append(r.Signals, model.Signal{Path: file.Path, Line: 5, EndLine: 10, Severity: "high"})
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Finalize(&r, false)
	}
}

func fmtPath(i int) string { return string(rune('a'+i)) + ".go" }

// coverageWeirdPath carries every Markdown metacharacter the renderer must
// neutralize, plus a newline that would otherwise open a forged heading.
const coverageWeirdPath = "internal/*cov*/_[file]|name#one.go\n# Injected Heading"

// coverageWeirdPathEscaped is what inline() must produce: control runes become
// spaces and every metacharacter is backslash-escaped.
const coverageWeirdPathEscaped = `internal/\*cov\*/\_\[file\]\|name\#one.go \# Injected Heading`

const coverageWeirdReason = "profile *missing*: see _[docs]_|run#now"
const coverageWeirdReasonEscaped = `profile \*missing\*: see \_\[docs\]\_\|run\#now`

// measuredCoverage is a recorded, internally consistent measurement: 7+3+1+1
// added lines resolved into the four states, beside 4 removed lines that have
// no candidate-side coordinate and so sit outside that sum.
func measuredCoverage() model.Coverage {
	return model.Coverage{
		Status:           coverage.StatusMeasured,
		CheckID:          "cov-1",
		ProfileSHA256:    strings.Repeat("a", 64),
		Command:          []string{"go", "test", "-covermode=count", "-coverprofile=/tmp/swiftproof-coverage.out", "./..."},
		AddedLines:       12,
		ExecutedLines:    7,
		NotExecutedLines: 3,
		NoBlockLines:     1,
		NotMeasuredLines: 1,
		RemovedLines:     4,
		Files: []model.CoverageFile{{
			Path:             coverageWeirdPath,
			Status:           coverage.StatusMeasured,
			AddedLines:       12,
			ExecutedLines:    7,
			NotExecutedLines: 3,
			NoBlockLines:     1,
			NotMeasuredLines: 1,
		}},
		Note: coverage.Note,
	}
}

// section returns the body of one rendered Markdown section, up to the next one.
func section(t *testing.T, md, heading string) string {
	t.Helper()
	i := strings.Index(md, heading+"\n")
	if i < 0 {
		t.Fatalf("report has no %q section:\n%s", heading, md)
	}
	body := md[i+len(heading)+1:]
	if j := strings.Index(body, "\n## "); j >= 0 {
		body = body[:j]
	}
	return body
}

// strayHeadings returns every heading line the renderer does not itself emit.
func strayHeadings(md string) []string {
	known := map[string]bool{
		"# Change Confidence Report": true,
		"## Change Summary":          true,
		"## Automated Checks":        true,
		"## Investigation Summary":   true,
		"## Reproduced Issues":       true,
		"## Unverified Areas":        true,
		"## Suggested Human Review":  true,
		"## Review Surface":          true,
		"## Changed-line Execution":  true,
		"## Recorded Evidence":       true,
		"## Artifacts":               true,
	}
	var out []string
	for _, l := range strings.Split(md, "\n") {
		if strings.HasPrefix(l, "#") && !known[l] {
			out = append(out, l)
		}
	}
	return out
}

// unescaped reports whether s holds an occurrence of c that no backslash guards.
func unescaped(s string, c byte) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == c && (i == 0 || s[i-1] != '\\') {
			return true
		}
	}
	return false
}

func hasString(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}

// A measured coverage section is rendered from model strings, so every one of
// them must leave inline() inert: no live metacharacter and no forged heading.
func TestCoverageSectionRendersAndEscapes(t *testing.T) {
	r := &model.Report{Coverage: measuredCoverage()}
	r.Coverage.Reason = coverageWeirdReason
	md := string(Markdown(r))
	body := section(t, md, "## Changed-line Execution")

	const sentence = "Measured from check cov-1: of 12 added Go lines, 7 were executed at least once, 3 were not executed, 1 are not inside any instrumented block, 1 could not be measured. 4 removed lines cannot be executed by a candidate-side run and are excluded."
	if !strings.Contains(body, sentence) {
		t.Fatalf("measured sentence does not match the implementation verbatim; section:\n%s", body)
	}
	const fileLine = "- " + coverageWeirdPathEscaped + ": 7 executed, 3 not executed, 1 not inside any instrumented block, 1 not measured"
	if !strings.Contains(body, fileLine) {
		t.Fatalf("per-file line is not the escaped form; section:\n%s", body)
	}
	if !strings.Contains(body, coverage.Note) {
		t.Fatal("measured section omits the note stating what execution does not establish")
	}
	// Nothing hostile survives into the document, from either field.
	if strings.Contains(md, coverageWeirdPath) {
		t.Fatal("raw coverage path reached the rendered report unescaped")
	}
	if strings.Contains(md, coverageWeirdReason) {
		t.Fatal("raw coverage reason reached the rendered report unescaped")
	}
	// Every metacharacter inside the section body came through inline(), so an
	// unguarded one can only mean an injection succeeded.
	for _, c := range []byte{'*', '_', '[', ']', '|', '#', '(', ')', '!', '`'} {
		if unescaped(body, c) {
			t.Errorf("unescaped %q in the Changed-line Execution section:\n%s", string(c), body)
		}
	}
	if stray := strayHeadings(md); len(stray) > 0 {
		t.Fatalf("coverage strings produced stray headings: %q", stray)
	}
}

// Anything short of a complete measurement says so in words. It must never fall
// back on counters, whose zeros would read as "nothing was left unexecuted".
func TestCoverageNotMeasuredRendersExplicitly(t *testing.T) {
	tests := []struct {
		name   string
		reason string
		want   string
	}{
		{"plain reason", "the coverage payload frame was truncated", "Changed-line execution was not measured: the coverage payload frame was truncated"},
		{"markdown metacharacters", coverageWeirdReason, "Changed-line execution was not measured: " + coverageWeirdReasonEscaped},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &model.Report{Coverage: coverage.NotMeasured(tt.reason).Report()}
			md := string(Markdown(r))
			body := section(t, md, "## Changed-line Execution")
			if !strings.Contains(body, tt.want) {
				t.Fatalf("not-measured reason not stated explicitly; section:\n%s", body)
			}
			for _, forbidden := range []string{"Measured from check", "were executed at least once", "not inside any instrumented block", "No coverage command is configured"} {
				if strings.Contains(body, forbidden) {
					t.Errorf("absent coverage data rendered as a measured result: %q in\n%s", forbidden, body)
				}
			}
			// Neither reason above holds a digit, so any digit here is a count,
			// and a count in this state could only be a zero passing for
			// complete coverage.
			for i := 0; i < len(body); i++ {
				if body[i] >= '0' && body[i] <= '9' {
					t.Fatalf("not-measured section reports a count that could read as full coverage:\n%s", body)
				}
			}
		})
	}
}

// A report written before the coverage field existed unmarshals with the zero
// value. It must normalize to "nothing was measured", never to a claim.
func TestCoverageNotConfiguredAfterFinalizeOnLegacyReport(t *testing.T) {
	const legacy = `{"version":1,"change":{"files":[]},"linter":[],"checks":[],"hypotheses":[],"evidence":[]}`
	var r model.Report
	if err := json.Unmarshal([]byte(legacy), &r); err != nil {
		t.Fatal(err)
	}
	if r.Coverage.Status != "" || r.Coverage.Note != "" || r.Coverage.Files != nil {
		t.Fatalf("fixture is not the zero value: %+v", r.Coverage)
	}
	Finalize(&r, true)
	if r.Coverage.Status != coverage.StatusNotConfigured {
		t.Fatalf("absent coverage data reported as %q, want %q", r.Coverage.Status, coverage.StatusNotConfigured)
	}
	if r.Coverage.Note != coverage.Note {
		t.Fatal("normalized coverage omits the note stating what execution does not establish")
	}
	if r.Coverage.Files == nil {
		t.Fatal("normalized coverage files is nil rather than an empty slice")
	}
	if len(r.Coverage.Files) != 0 || r.Coverage.AddedLines != 0 || r.Coverage.NotExecutedLines != 0 {
		t.Fatalf("legacy report gained coverage claims: %+v", r.Coverage)
	}
	md := string(Markdown(&r))
	if !strings.Contains(md, "No coverage command is configured, so changed-line execution was not measured.") {
		t.Fatalf("not-configured sentence missing:\n%s", section(t, md, "## Changed-line Execution"))
	}
}

// The attribution notice is an AGPL section 7(b) term and must stay in every report.
func TestMarkdownCarriesAttribution(t *testing.T) {
	r := proofReport()
	r.ToolVersion = "v1.2.3"
	md := string(Markdown(r))
	if !strings.HasSuffix(md, "Generated by SwiftProof v1.2.3 (https://github.com/gvinsot/SwiftProof).\n") {
		t.Fatalf("attribution notice missing from report end:\n%s", md)
	}
}

// Coverage is recorded upstream. Finalize normalizes the empty case and is
// otherwise a pure pass-through, so re-rendering a persisted report is stable.
func TestFinalizeIdempotentWithCoverage(t *testing.T) {
	r := proofReport()
	r.Coverage = measuredCoverage()
	want := measuredCoverage()
	Finalize(r, true)
	first, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	Finalize(r, true)
	second, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatal("Finalize is not idempotent once a coverage measurement is present")
	}
	if !reflect.DeepEqual(r.Coverage, want) {
		t.Fatalf("Finalize recomputed or cleared a measured coverage:\ngot  %+v\nwant %+v", r.Coverage, want)
	}
}

// A nil file list means "no file reported", not "no such field"; JSON null
// would leave a consumer guessing which one it is.
func TestCoverageFilesSerializeAsArray(t *testing.T) {
	tests := []struct {
		name string
		cov  model.Coverage
	}{
		{"zero value", model.Coverage{}},
		{"measured with no reported file", model.Coverage{Status: coverage.StatusMeasured, CheckID: "cov-1", AddedLines: 3, ExecutedLines: 3, Note: coverage.Note}},
		{"not measured", model.Coverage{Status: coverage.StatusNotMeasured, Reason: "no go.mod", Note: coverage.Note}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &model.Report{Version: 1, Coverage: tt.cov}
			dir := t.TempDir()
			if err := Write(dir, r, []string{"json"}); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(filepath.Join(dir, "confidence-report.json"))
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(data), "null") {
				t.Errorf("a nil slice serialized as null:\n%s", data)
			}
			var saved map[string]any
			if err := json.Unmarshal(data, &saved); err != nil {
				t.Fatal(err)
			}
			cov, ok := saved["coverage"].(map[string]any)
			if !ok {
				t.Fatalf("coverage must be a JSON object, got %#v", saved["coverage"])
			}
			if values, ok := cov["files"].([]any); !ok || len(values) != 0 {
				t.Fatalf("coverage.files must be an empty JSON array, got %#v", cov["files"])
			}
			if r.Coverage.Files != nil {
				t.Fatal("serialization mutated caller's report")
			}
		})
	}
}

// Coverage is recorded as a report, never as evidence. Finalize only ever reads
// r.Evidence, so a measurement that creates no evidence record cannot be cited
// by any hypothesis - which is exactly what stops "the line was executed" from
// ever being used to support a DISMISSED verdict.
func TestCoverageCreatesNoEvidenceRecord(t *testing.T) {
	plain := proofReport()
	Finalize(plain, true)

	measured := proofReport()
	measured.Coverage = measuredCoverage()
	measured.Signals = []model.Signal{{ID: "cov-sig-1", Kind: coverage.Kind, Path: "internal/a/a.go", Line: 21, EndLine: 21, Side: "new", Severity: "medium", Summary: "Added lines were not executed by any instrumented package in the coverage run"}}
	// A hypothesis that tries to lean on the measurement instead of a recorded
	// source observation can only cite an ID no evidence record carries.
	measured.Hypotheses = append(measured.Hypotheses, model.Hypothesis{ID: "h2", Title: "Dead branch", Severity: "medium", Status: "DISMISSED", Rationale: "the coverage run executed it", EvidenceIDs: []string{"cov-1"}})
	Finalize(measured, true)

	if len(measured.Evidence) != len(plain.Evidence) {
		t.Fatalf("coverage created %d evidence records", len(measured.Evidence)-len(plain.Evidence))
	}
	for _, e := range measured.Evidence {
		kind := strings.ToLower(e.Kind)
		if strings.Contains(kind, "coverage") || strings.Contains(kind, "covered") || strings.Contains(kind, "execution") {
			t.Fatalf("coverage was recorded as citable evidence: %+v", e)
		}
	}
	if got := measured.Hypotheses[1].Status; got != "UNVERIFIED" {
		t.Fatalf("dismissal backed only by a coverage measurement was accepted as %s", got)
	}
	if measured.Hypotheses[0].Status != plain.Hypotheses[0].Status {
		t.Fatalf("coverage changed an existing verdict: %s became %s", plain.Hypotheses[0].Status, measured.Hypotheses[0].Status)
	}
}

// An uncovered_change signal is an ordinary signal: it must land on the changed
// coordinates it names and carry its summary into the human review list.
func TestUncoveredSignalsReachReviewTargets(t *testing.T) {
	const summary = "Added lines were not executed by any instrumented package in the coverage run"
	r := &model.Report{
		Change: model.Change{Files: []model.ChangedFile{{Path: "internal/a/a.go", Status: "M", Hunks: []model.Hunk{{Lines: []model.DiffLine{
			{Kind: "add", NewLine: 21, Content: "if err != nil {"},
			{Kind: "add", NewLine: 22, Content: "\treturn err"},
			{Kind: "add", NewLine: 23, Content: "}"},
			{Kind: "context", NewLine: 24, OldLine: 20, Content: "return nil"},
		}}}}}},
		Signals: []model.Signal{{ID: "cov-sig-1", Kind: coverage.Kind, Path: "internal/a/a.go", Line: 21, EndLine: 22, Side: "new", Severity: "medium", Summary: summary}},
	}
	Finalize(r, true)
	if len(r.ReviewTargets) != 1 {
		t.Fatalf("uncovered_change signal produced %d targets: %+v", len(r.ReviewTargets), r.ReviewTargets)
	}
	got := r.ReviewTargets[0]
	if got.Path != "internal/a/a.go" || got.Side != "new" || got.StartLine != 21 || got.EndLine != 22 {
		t.Fatalf("target is not at the changed coordinates the signal named: %+v", got)
	}
	if got.Severity != "medium" {
		t.Fatalf("uncovered_change severity became %q", got.Severity)
	}
	if !hasString(got.Reasons, summary) {
		t.Fatalf("signal summary is not a review reason: %+v", got.Reasons)
	}
	if !hasString(got.SignalIDs, "cov-sig-1") {
		t.Fatalf("signal ID is not attached to the target: %+v", got.SignalIDs)
	}
	// Line 23 is changed but unclaimed: coverage prioritizes, it never shrinks
	// the changed surface a human still owns.
	if r.ReviewSurface.ChangedLines != 3 || r.ReviewSurface.FocusedLines != 2 {
		t.Fatalf("bad surface %+v", r.ReviewSurface)
	}
	if !strings.Contains(string(Markdown(r)), summary) {
		t.Fatal("uncovered_change summary missing from the rendered review list")
	}
}

func jestProofReport() *model.Report {
	r := proofReport()
	command := []string{"npx", "--no", "vitest", "run", "src/cart.test.ts", "--reporter=json", "--outputFile=/tmp/swiftproof-test-results.json"}
	result := func(status string) string {
		return `{"testResults":[{"name":"/workspace/src/cart.test.ts","assertionResults":[{"ancestorTitles":[],"title":"applies the discount once","status":"` + status + `"}]}]}`
	}
	r.Checks[0].Command, r.Checks[0].Output, r.Checks[0].Results = command, "", result("passed")
	r.Checks[1].Command, r.Checks[1].Output, r.Checks[1].Results = command, "", result("failed")
	r.Evidence[0].Runner, r.Evidence[0].Path, r.Evidence[0].TestNames = "jest_json", "src/cart.test.ts", []string{"applies the discount once"}
	return r
}

func TestFinalizeValidatesJestDifferentialProof(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*model.Report)
		status string
	}{
		{"valid", func(*model.Report) {}, "REPRODUCED"},
		{"results only in log", func(r *model.Report) { r.Checks[1].Output, r.Checks[1].Results = r.Checks[1].Results, "" }, "UNVERIFIED"},
		{"other file", func(r *model.Report) { r.Evidence[0].Path = "src/other.test.ts" }, "UNVERIFIED"},
		{"unrelated title", func(r *model.Report) { r.Evidence[0].TestNames = []string{"something else"} }, "UNVERIFIED"},
		{"baseline skipped", func(r *model.Report) {
			r.Checks[0].Results = strings.Replace(r.Checks[0].Results, "passed", "skipped", 1)
		}, "UNVERIFIED"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := jestProofReport()
			tt.mutate(r)
			Finalize(r, true)
			if r.Hypotheses[0].Status != tt.status {
				t.Fatalf("got status %s", r.Hypotheses[0].Status)
			}
		})
	}
}
