package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gvinsot/SwiftProof/app/internal/model"
	"github.com/gvinsot/SwiftProof/app/internal/redact"
)

// roundTripReport holds secret-shaped content in the places a run can record
// it: a check log, structured results (a Redact fixed point, as the harness
// records them, and a failure message that is not), a hypothesis rationale and
// a test name.
func roundTripReport() *model.Report {
	r := jestProofReport()
	r.ToolVersion = "v0.4.0-test"
	r.GeneratedAt = time.Date(2026, 9, 25, 10, 0, 0, 0, time.UTC)
	r.Change = model.Change{BaseRef: "main", BaseCommit: strings.Repeat("a", 40), HeadCommit: strings.Repeat("b", 40), Files: []model.ChangedFile{{Path: "src/cart.ts", Status: "M", Additions: 1, Hunks: []model.Hunk{{NewStart: 3, NewLines: 1, Lines: []model.DiffLine{{Kind: "add", NewLine: 3, Content: "return total - 10"}}}}}}}
	failed := `{"testResults":[{"name":"/workspace/src/cart.test.ts","message":"","assertionResults":[{"ancestorTitles":[],"title":"applies the discount once","status":"failed","failureMessages":["expected [REDACTED] to be 3","password=hunter2 leaked"]}]}]}`
	r.Checks[1].Results = failed
	r.Checks[0].Output = "curl -H Bearer abc.def.ghi\nrunning vitest"
	r.Checks[1].Output = "api_key=sk-live-0123456789abcdef\n"
	r.Hypotheses[0].Rationale = "the fixture used token=ghp_0123456789abcdefghij"
	r.Hypotheses[0].Path, r.Hypotheses[0].Line = "src/cart.ts", 3
	// A second, Go experiment whose test name is secret-shaped. It is
	// UNVERIFIED before and after sanitizing, never promoted by a re-render.
	const secretName = "TestAKIA0123456789ABCDEF"
	command := []string{"go", "test", "-json", "-count=1", "-run", "^" + secretName + "$", "."}
	r.Checks = append(r.Checks,
		model.Check{ID: "check-3", Kind: model.CheckGeneratedBase, Status: "PASS", Command: command, Output: strings.ReplaceAll(goPass, "TestRegression", secretName)},
		model.Check{ID: "check-4", Kind: model.CheckGeneratedCandidate, Status: "FAIL", ExitCode: 1, Command: command, Output: strings.ReplaceAll(goFail, "TestRegression", secretName)},
	)
	r.Evidence = append(r.Evidence, model.Evidence{ID: "evidence-2", Kind: model.EvidenceDifferentialTest, Status: model.StatusReproduced, BaseCheckID: "check-3", CheckID: "check-4", Runner: "go_test_json", TestNames: []string{secretName}})
	r.Hypotheses = append(r.Hypotheses, model.Hypothesis{ID: "h2", Title: "Secret-named test", Severity: "critical", Status: "REPRODUCED", EvidenceIDs: []string{"evidence-2"}})
	r.Unverified = []string{"reviewer note with password: swordfish"}
	return r
}

func writeAndRead(t *testing.T, dir string, r *model.Report) ([]byte, []byte) {
	t.Helper()
	if err := Write(dir, r, []string{FormatJSON, FormatMarkdown}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "confidence-report.json"))
	if err != nil {
		t.Fatal(err)
	}
	md, err := os.ReadFile(filepath.Join(dir, "CONFIDENCE_REPORT.md"))
	if err != nil {
		t.Fatal(err)
	}
	return data, md
}

// Write -> Unmarshal -> Finalize -> Write yields byte-identical reports, and
// the verdicts do not move when the stored strings are redacted.
func TestFinalizeRoundTripWithSecretShapedResults(t *testing.T) {
	r := roundTripReport()
	Finalize(r, true)
	if r.Hypotheses[0].Status != model.StatusReproduced || r.Hypotheses[1].Status != model.StatusUnverified || r.ExitCode != 1 {
		t.Fatalf("first finalize: %s %s exit %d", r.Hypotheses[0].Status, r.Hypotheses[1].Status, r.ExitCode)
	}
	firstJSON, firstMD := writeAndRead(t, t.TempDir(), r)
	for _, secret := range []string{"hunter2", "swordfish", "sk-live", "ghp_0123", "abc.def.ghi", "AKIA0123456789ABCDEF"} {
		if strings.Contains(string(firstJSON), secret) || strings.Contains(string(firstMD), secret) {
			t.Fatalf("secret %q reached the written report", secret)
		}
	}
	var loaded model.Report
	if err := json.Unmarshal(firstJSON, &loaded); err != nil {
		t.Fatal(err)
	}
	if redact.Redact(loaded.Checks[1].Results) != loaded.Checks[1].Results {
		t.Fatal("stored results are not a fixed point of Redact")
	}
	Finalize(&loaded, true)
	if loaded.Hypotheses[0].Status != model.StatusReproduced || loaded.Hypotheses[1].Status != model.StatusUnverified || loaded.ExitCode != 1 {
		t.Fatalf("re-finalize moved a verdict: %s %s exit %d", loaded.Hypotheses[0].Status, loaded.Hypotheses[1].Status, loaded.ExitCode)
	}
	secondJSON, secondMD := writeAndRead(t, t.TempDir(), &loaded)
	if string(firstJSON) != string(secondJSON) {
		t.Fatalf("JSON changed on re-render:\n%s\n---\n%s", firstJSON, secondJSON)
	}
	if string(firstMD) != string(secondMD) {
		t.Fatalf("Markdown changed on re-render:\n%s\n---\n%s", firstMD, secondMD)
	}
	// Finalizing twice in memory is also stable.
	before, _ := json.Marshal(&loaded)
	Finalize(&loaded, true)
	after, _ := json.Marshal(&loaded)
	if string(before) != string(after) {
		t.Fatal("Finalize is not idempotent in memory")
	}
}

func TestFinalizeResetsDerivedFields(t *testing.T) {
	r := &model.Report{
		Version:            7,
		ExitCode:           1,
		ReproducedIssues:   []model.Hypothesis{{ID: "forged", Status: model.StatusReproduced}},
		Divergences:        []model.Divergence{{EvidenceID: "forged", Kind: model.EvidenceDifferentialFuzz}},
		IntentTestFailures: []model.Hypothesis{{ID: "forged", Status: model.StatusIntentTestFailed}},
		ReviewTargets:      []model.ReviewTarget{{Path: "forged.go"}},
	}
	Finalize(r, true)
	if r.Version != 1 || r.ExitCode != 0 || len(r.ReproducedIssues) != 0 || len(r.Divergences) != 0 || len(r.IntentTestFailures) != 0 || len(r.ReviewTargets) != 0 {
		t.Fatalf("forged derived fields survived Finalize: %+v", r)
	}
}

// Optional sections are present exactly when set; the always-present arrays
// are arrays.
func TestOptionalSectionsPresentOnlyWhenSet(t *testing.T) {
	keys := []string{"prepare", "base_tests", "mutation", "fuzz", "impact", "execution"}
	read := func(r *model.Report) map[string]any {
		t.Helper()
		dir := t.TempDir()
		if err := Write(dir, r, []string{FormatJSON}); err != nil {
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
		return saved
	}
	saved := read(&model.Report{Version: 1})
	for _, k := range keys {
		if _, ok := saved[k]; ok {
			t.Errorf("%s present although not requested", k)
		}
	}
	r := &model.Report{Version: 1, Prepare: &model.Prepare{Status: model.PrepareNotRun}, BaseTests: &model.BaseTests{Status: model.BaseTestsNoCandidates},
		Mutation: &model.Mutation{Status: model.MutationNotRun}, Fuzz: &model.FuzzReport{Status: model.FuzzDisabled},
		Impact: &model.Impact{Status: model.ImpactUnavailable}, Execution: &model.Execution{}}
	saved = read(r)
	for _, k := range keys {
		if _, ok := saved[k].(map[string]any); !ok {
			t.Errorf("%s absent although set", k)
		}
	}
	// Nested slices of present sections are arrays too.
	for path, value := range map[string]any{
		"mutation.mutants":         saved["mutation"].(map[string]any)["mutants"],
		"mutation.checks":          saved["mutation"].(map[string]any)["checks"],
		"fuzz.functions":           saved["fuzz"].(map[string]any)["functions"],
		"impact.changed_functions": saved["impact"].(map[string]any)["changed_functions"],
		"base_tests.tests":         saved["base_tests"].(map[string]any)["tests"],
		"prepare.inputs":           saved["prepare"].(map[string]any)["inputs"],
		"execution.replay_backed":  saved["execution"].(map[string]any)["replay_backed"],
	} {
		if values, ok := value.([]any); !ok || len(values) != 0 {
			t.Errorf("%s must be an empty JSON array, got %#v", path, value)
		}
	}
}
