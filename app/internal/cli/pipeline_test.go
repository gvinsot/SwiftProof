package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gvinsot/SwiftProof/app/internal/coverage"
	"github.com/gvinsot/SwiftProof/app/internal/model"
)

const absentImage = "swiftproof.invalid/absent:test-only"

// runReport runs the CLI and returns the exit code, the decoded report and the
// raw JSON of its top-level members.
func runReport(t *testing.T, ctx context.Context, dir string, args ...string) (int, model.Report, map[string]json.RawMessage, string) {
	t.Helper()
	out := filepath.Join(t.TempDir(), "report")
	var stdout, stderr bytes.Buffer
	code := Run(ctx, append(append([]string{}, args...), "--repo", dir, "--out", out), &stdout, &stderr, "test")
	if code == 3 {
		t.Fatalf("%v exited 3: %s", args, stderr.String())
	}
	data, err := os.ReadFile(filepath.Join(out, "confidence-report.json"))
	if err != nil {
		t.Fatalf("%v wrote no report (exit %d): %v\n%s", args, code, err, stderr.String())
	}
	var r model.Report
	if err := json.Unmarshal(data, &r); err != nil {
		t.Fatal(err)
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(data, &members); err != nil {
		t.Fatal(err)
	}
	return code, r, members, stdout.String() + stderr.String()
}

// Lint never prepares, fuzzes or mutates, even with those keys in policy; it
// records the static impact object unless --impact=false; the three new arrays
// serialize as [].
func TestLintSectionsFollowPresentMeansRequested(t *testing.T) {
	dir := fixture(t)
	forbidExecution(t)
	policy := v04Policy(t, absentImage, nil)
	code, r, members, _ := runReport(t, context.Background(), dir, "lint", "--config", policy)
	if code != 0 {
		t.Fatalf("lint exit %d", code)
	}
	for _, key := range []string{"prepare", "fuzz", "mutation", "base_tests", "execution"} {
		if _, ok := members[key]; ok {
			t.Errorf("lint report has %q", key)
		}
	}
	for _, key := range []string{"intent_criteria", "divergences", "intent_test_failures"} {
		if string(members[key]) != "[]" {
			t.Errorf("%s = %s, want []", key, members[key])
		}
	}
	if r.Impact == nil || r.Impact.Status == "" || r.Impact.ChangedFunctions == nil || r.Impact.Note == "" || r.Impact.TestsStatus != "" {
		t.Fatalf("lint impact section %+v", r.Impact)
	}
	if len(r.Checks) != 0 {
		t.Fatal("lint executed repository code")
	}
	_, _, members, _ = runReport(t, context.Background(), dir, "lint", "--config", policy, "--impact=false")
	if _, ok := members["impact"]; ok {
		t.Fatal("--impact=false still wrote an impact section")
	}
}

// With --checks=false nothing executes; configured stages still record their
// sections: fuzz disabled, mutation not_run, prepare not_run.
func TestChecksDisabledRecordsConfiguredStages(t *testing.T) {
	dir := fixture(t)
	forbidExecution(t)
	policy := v04Policy(t, absentImage, nil)
	code, r, _, _ := runReport(t, context.Background(), dir, "review", "--config", policy, "--checks=false", "--reviewer=false", "--ci")
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	if r.Fuzz == nil || r.Fuzz.Status != model.FuzzDisabled {
		t.Fatalf("fuzz %+v, want disabled", r.Fuzz)
	}
	if r.Mutation == nil || r.Mutation.Status != model.MutationNotRun || r.Mutation.Reason != "initial checks disabled (--checks=false)" {
		t.Fatalf("mutation %+v, want not_run", r.Mutation)
	}
	if r.Prepare == nil || r.Prepare.Status != model.PrepareNotRun || r.Prepare.Reason != reasonExecutionDisabled || r.Prepare.SourceCommit != r.Change.BaseCommit {
		t.Fatalf("prepare %+v, want not_run with the execution reason", r.Prepare)
	}
	if r.BaseTests != nil || (r.Impact != nil && r.Impact.TestsStatus != "") {
		t.Fatal("stages that were not requested recorded a section")
	}
	_, r, _, _ = runReport(t, context.Background(), dir, "review", "--config", policy, "--checks=false", "--fuzz=false", "--reviewer=false")
	if r.Fuzz == nil || r.Fuzz.Status != model.FuzzDisabled || r.Fuzz.Reason != "--fuzz=false" {
		t.Fatalf("fuzz %+v, want disabled by --fuzz=false", r.Fuzz)
	}
}

// An empty change records no_candidates for every requested stage, and prepare
// did not need to run.
func TestEmptyChangeRecordsNoCandidates(t *testing.T) {
	dir := fixture(t)
	forbidExecution(t)
	policy := v04Policy(t, absentImage, nil)
	code, r, _, _ := runReport(t, context.Background(), dir, "review", "--head", "main", "--config", policy, "--base-tests", "--impacted-tests", "--ci")
	if code != 0 {
		t.Fatalf("exit %d, want 0: %+v", code, r.Unverified)
	}
	if r.Fuzz == nil || r.Fuzz.Status != model.FuzzNoCandidates {
		t.Fatalf("fuzz %+v", r.Fuzz)
	}
	if r.Mutation == nil || r.Mutation.Status != model.MutationNoCandidates {
		t.Fatalf("mutation %+v", r.Mutation)
	}
	if r.BaseTests == nil || r.BaseTests.Status != model.BaseTestsNoCandidates {
		t.Fatalf("base tests %+v", r.BaseTests)
	}
	if r.Impact == nil || r.Impact.TestsStatus != model.ImpactTestsNoCandidates {
		t.Fatalf("impact %+v", r.Impact)
	}
	if r.Prepare == nil || r.Prepare.Status != model.PrepareNotRun || r.Prepare.Reason != reasonNoChangedFiles {
		t.Fatalf("prepare %+v", r.Prepare)
	}
}

// A failed preparation runs nothing else, never falls back to the unprepared
// image, exits 4, and every requested stage records why it did not run.
func TestFailedPreparationRunsNoRepositoryCode(t *testing.T) {
	dir := fixture(t)
	calls := countExecution(t)
	policy := v04Policy(t, absentImage, nil)
	code, r, _, _ := runReport(t, context.Background(), dir, "review", "--config", policy, "--base-tests", "--impacted-tests", "--reviewer=false")
	if code != 4 {
		t.Fatalf("exit %d, want 4", code)
	}
	if *calls != 1 {
		t.Fatalf("execution hook called %d times, want once (prepare only)", *calls)
	}
	if len(r.Checks) != 0 {
		t.Fatalf("checks ran after a failed preparation: %v", checkKinds(r))
	}
	if r.Prepare == nil || r.Prepare.Status == model.PrepareBuilt || r.Prepare.Status == model.PrepareReused || r.Prepare.Status == model.PrepareNotRun {
		t.Fatalf("prepare %+v, want a failure status", r.Prepare)
	}
	if r.Fuzz == nil || r.Mutation == nil || r.BaseTests == nil || r.Impact == nil {
		t.Fatalf("a requested stage recorded no section: fuzz %+v mutation %+v base %+v impact %+v", r.Fuzz, r.Mutation, r.BaseTests, r.Impact)
	}
	for name, status := range map[string]string{"fuzz": r.Fuzz.Status, "mutation": r.Mutation.Status, "base tests": r.BaseTests.Status, "impacted tests": r.Impact.TestsStatus} {
		if status != "not_run" {
			t.Errorf("%s status %q, want not_run", name, status)
		}
	}
	if r.Fuzz.Reason != reasonPrepareFailed || r.Mutation.Reason != reasonPrepareFailed || r.BaseTests.Reason != reasonPrepareFailed || r.Impact.TestsReason != reasonPrepareFailed {
		t.Fatalf("stage reasons %q %q %q %q", r.Fuzz.Reason, r.Mutation.Reason, r.BaseTests.Reason, r.Impact.TestsReason)
	}
	for _, u := range r.Unverified {
		if strings.Contains(u, "explicitly disabled") {
			t.Fatalf("a failed preparation was reported as disabled execution: %q", u)
		}
	}
}

// With checks on, every configured or requested stage records its section,
// initial checks run in their fixed order and in one progress line, and
// coverage runs after them. The image does not exist, so no repository code
// runs whether or not Docker is installed.
func TestStagesRecordSectionsInOrder(t *testing.T) {
	dir := fixture(t)
	calls := countExecution(t)
	policy := v04Policy(t, absentImage, func(p map[string]any) { delete(p, "prepare") })
	code, r, _, output := runReport(t, context.Background(), dir, "review", "--config", policy, "--base-tests", "--impacted-tests", "--reviewer=false")
	if code != 4 {
		t.Fatalf("exit %d, want 4 (the sandbox image does not exist)", code)
	}
	if *calls != 1 {
		t.Fatalf("execution hook called %d times, want once (the harness)", *calls)
	}
	if !strings.Contains(output, "Running test, typecheck, build in isolated Docker sandboxes...") {
		t.Fatalf("missing the combined progress line:\n%s", output)
	}
	kinds := checkKinds(r)
	if len(kinds) < 4 || strings.Join(kinds[:4], ",") != "test,typecheck,build,"+coverage.CommandKey {
		t.Fatalf("check order %v", kinds)
	}
	if r.Fuzz == nil || r.Mutation == nil || r.BaseTests == nil || r.Impact == nil || r.Impact.TestsStatus == "" {
		t.Fatalf("a requested stage recorded no section: fuzz %+v mutation %+v base %+v impact %+v", r.Fuzz, r.Mutation, r.BaseTests, r.Impact)
	}
	if r.Prepare != nil {
		t.Fatal("prepare recorded without a prepare policy")
	}
}

// Reaching --deadline records SKIPPED runs and the deadline entry; it requests
// human review under --ci and never yields exit 4 by itself.
func TestDeadlineReachedIsNotAnOperationalFailure(t *testing.T) {
	dir := fixture(t)
	policy := coveragePolicy(t)
	for _, ci := range []bool{false, true} {
		ctx := withStart(context.Background(), time.Now().Add(-2*time.Minute))
		args := []string{"review", "--config", policy, "--deadline", "1m", "--reviewer=false"}
		if ci {
			args = append(args, "--ci")
		}
		code, r, _, _ := runReport(t, ctx, dir, args...)
		want := 0
		if ci {
			want = 2
		}
		if code != want {
			t.Fatalf("ci=%v: exit %d, want %d", ci, code, want)
		}
		if len(r.Checks) == 0 {
			t.Fatal("no check was recorded")
		}
		for _, c := range r.Checks {
			if c.Status != "SKIPPED" {
				t.Fatalf("check %s ran after the deadline: %s", c.ID, c.Status)
			}
		}
		found := false
		for _, u := range r.Unverified {
			found = found || u == deadlineNote
		}
		if !found {
			t.Fatalf("missing deadline entry: %q", r.Unverified)
		}
	}
}

// init never writes the release-ordered policy keys, whatever the language.
func TestInitWritesNoReleaseOrderedKeys(t *testing.T) {
	for _, language := range []string{"go", "typescript", "javascript", "python", "unknown"} {
		dir := t.TempDir()
		var out, errOut bytes.Buffer
		if code := Run(context.Background(), []string{"init", "--repo", dir, "--language", language}, &out, &errOut, "test"); code != 0 {
			t.Fatalf("init %s: %d %s", language, code, errOut.String())
		}
		data, err := os.ReadFile(filepath.Join(dir, ".swiftproof.json"))
		if err != nil {
			t.Fatal(err)
		}
		var keys map[string]json.RawMessage
		if err := json.Unmarshal(data, &keys); err != nil {
			t.Fatal(err)
		}
		for _, key := range []string{"fuzz", "mutation", "prepare"} {
			if _, ok := keys[key]; ok {
				t.Errorf("init %s wrote %q", language, key)
			}
		}
	}
}
