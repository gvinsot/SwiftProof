package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gvinsot/SwiftProof/internal/model"
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
