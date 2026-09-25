package cli

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/gvinsot/SwiftProof/app/internal/config"
	"github.com/gvinsot/SwiftProof/app/internal/model"
)

func TestNoExecutionReason(t *testing.T) {
	changed := model.Change{Files: []model.ChangedFile{{Path: "a.go"}}}
	for _, tc := range []struct {
		mode             string
		change           model.Change
		checks, reviewer bool
		want             string
	}{
		{"lint", changed, false, false, reasonLint},
		{"review", model.Change{}, true, true, reasonNoChangedFiles},
		{"review", changed, false, false, reasonExecutionDisabled},
		{"review", changed, true, false, ""},
		{"review", changed, false, true, ""},
	} {
		if got := noExecutionReason(tc.mode, tc.change, tc.checks, tc.reviewer); got != tc.want {
			t.Errorf("noExecutionReason(%s, %d files, %v, %v) = %q, want %q", tc.mode, len(tc.change.Files), tc.checks, tc.reviewer, got, tc.want)
		}
	}
}

func TestWorkContextDeadline(t *testing.T) {
	parent := context.Background()
	work, stop := workContext(parent, 0)
	stop()
	if work != parent {
		t.Fatal("a zero deadline must return the parent context itself")
	}
	start := time.Now().Add(-10 * time.Second)
	work, stop = workContext(withStart(parent, start), 10*time.Minute)
	defer stop()
	deadline, ok := work.Deadline()
	if !ok || !deadline.Equal(start.Add(10*time.Minute-30*time.Second)) {
		t.Fatalf("deadline %v (%v), want start + D - 30s = %v", deadline, ok, start.Add(10*time.Minute-30*time.Second))
	}
	before := time.Now()
	work, stop = workContext(parent, time.Minute)
	defer stop()
	deadline, _ = work.Deadline()
	if deadline.Before(before.Add(30*time.Second)) || deadline.After(time.Now().Add(30*time.Second)) {
		t.Fatalf("without a recorded start the deadline %v must count from now", deadline)
	}
}

func TestDeadlineReached(t *testing.T) {
	parent := context.Background()
	if deadlineReached(parent, parent) {
		t.Fatal("no deadline reported as reached")
	}
	expired, stop := workContext(withStart(parent, time.Now().Add(-time.Hour)), time.Minute)
	defer stop()
	<-expired.Done()
	if !deadlineReached(parent, expired) {
		t.Fatal("expired work context not reported")
	}
	cancelled, cancel := context.WithCancel(parent)
	work, stopWork := workContext(withStart(cancelled, time.Now().Add(-time.Hour)), time.Minute)
	defer stopWork()
	cancel()
	if deadlineReached(cancelled, work) {
		t.Fatal("a cancelled run is not a reached deadline")
	}
	live, stopLive := workContext(parent, time.Hour)
	defer stopLive()
	if deadlineReached(parent, live) {
		t.Fatal("a running deadline reported as reached")
	}
	if !errors.Is(expired.Err(), context.DeadlineExceeded) {
		t.Fatal("expired context has the wrong error")
	}
}

func TestReviewerReserve(t *testing.T) {
	cfg := config.Default("go")
	cfg.Sandbox.MaxRuntimeSeconds = 600
	if got := reviewerReserve(cfg, true); got != 300*time.Second {
		t.Fatalf("reserve %v, want half of 600 s", got)
	}
	if got := reviewerReserve(cfg, false); got != 0 {
		t.Fatalf("reserve without reviewer %v, want 0", got)
	}
	cfg.Sandbox.MaxRuntimeSeconds = 1
	if got := reviewerReserve(cfg, true); got != 500*time.Millisecond {
		t.Fatalf("reserve %v, want 500ms", got)
	}
}

func TestDivergenceLineAndStdoutOrder(t *testing.T) {
	r := &model.Report{}
	if divergenceLine(r) != "" || len(stdoutLines(r)) != 0 {
		t.Fatal("a report without divergences prints a divergence line")
	}
	r.Divergences = []model.Divergence{{EvidenceID: "evidence-1"}}
	if got := divergenceLine(r); got != "1 recorded behavior divergence (baseline and candidate recorded different values; a human decides which is intended)." {
		t.Fatalf("singular line %q", got)
	}
	r.Divergences = append(r.Divergences, model.Divergence{EvidenceID: "evidence-2"})
	want := "2 recorded behavior divergences (baseline and candidate recorded different values; a human decides which is intended)."
	if got := divergenceLine(r); got != want {
		t.Fatalf("line %q, want %q", got, want)
	}
	lines := stdoutLines(r)
	found := false
	for _, l := range lines {
		if l == "" {
			t.Fatal("stdoutLines returned an empty line")
		}
		if l == want {
			found = true
		}
	}
	// §5: a divergence is never presented as a defect or a verdict.
	for _, word := range []string{"regression", "bug", "correct", "defect", "%"} {
		if strings.Contains(strings.ToLower(want), word) {
			t.Fatalf("divergence line uses %q: %s", word, want)
		}
	}
	if !found {
		t.Fatalf("divergence line missing from %q", lines)
	}
}

func stageTestPolicy() config.Config {
	cfg := config.Default("go")
	cfg.Fuzz = &config.Fuzz{MaxInputs: 16}
	cfg.Mutation = &config.Mutation{Command: []string{"go", "test", "-json", "{package}"}, MaxMutants: 5, TimeoutSeconds: 30, MaxRuntimeSeconds: 60}
	return cfg
}

// The §1.7 record*Skipped table.
func TestRecordSkippedTable(t *testing.T) {
	cfg := stageTestPolicy()
	noFiles := stageContext{mode: "review", checks: true, reason: reasonNoChangedFiles}
	disabled := stageContext{mode: "review", checks: false, reason: reasonExecutionDisabled}
	reviewerOnly := stageContext{mode: "review", checks: false, executed: true}
	prepareFailed := stageContext{mode: "review", checks: true, reason: reasonPrepareFailed}
	lint := stageContext{mode: "lint", reason: reasonLint}

	type outcome struct{ status, reason string }
	fuzz := func(sc stageContext, enabled bool, c config.Config) *outcome {
		r := &model.Report{}
		recordFuzzSkipped(c, sc, enabled, r)
		if r.Fuzz == nil {
			return nil
		}
		f := r.Fuzz
		e := c.Fuzz.Effective(c.Sandbox)
		if f.SeedScheme != model.FuzzSeedScheme || f.Functions == nil || f.Skipped == nil || f.Note == "" || f.Limits.MaxInputs != e.MaxInputs || f.Limits.MaxRuntimeSeconds != e.MaxRuntimeSeconds {
			t.Fatalf("incomplete fuzz section %+v", f)
		}
		return &outcome{f.Status, f.Reason}
	}
	mutation := func(sc stageContext, c config.Config) *outcome {
		r := &model.Report{}
		recordMutationSkipped(c, sc, r)
		if r.Mutation == nil {
			return nil
		}
		m := r.Mutation
		if m.Files == nil || m.Mutants == nil || m.Checks == nil || m.Note == "" || m.Limits.MaxMutants != 5 || strings.Join(m.Command, " ") != "go test -json {package}" {
			t.Fatalf("incomplete mutation section %+v", m)
		}
		return &outcome{m.Status, m.Reason}
	}
	base := func(sc stageContext, requested bool) *outcome {
		r := &model.Report{}
		recordBaseTestsSkipped(sc, requested, r)
		if r.BaseTests == nil {
			return nil
		}
		if r.BaseTests.Tests == nil || r.BaseTests.Note == "" {
			t.Fatalf("incomplete base-tests section %+v", r.BaseTests)
		}
		return &outcome{r.BaseTests.Status, r.BaseTests.Reason}
	}
	impacted := func(sc stageContext, requested bool) *outcome {
		r := &model.Report{Impact: &model.Impact{Status: model.ImpactUnavailable}}
		recordImpactedTestsSkipped(sc, requested, r)
		if r.Impact.TestsStatus == "" {
			return nil
		}
		return &outcome{r.Impact.TestsStatus, r.Impact.TestsReason}
	}
	check := func(name string, got *outcome, status, reason string) {
		t.Helper()
		switch {
		case status == "" && got != nil:
			t.Errorf("%s: recorded %+v, want no-op", name, *got)
		case status != "" && got == nil:
			t.Errorf("%s: no-op, want %s", name, status)
		case status != "" && (got.status != status || reason != "" && got.reason != reason):
			t.Errorf("%s: recorded %+v, want %s (%s)", name, *got, status, reason)
		}
	}

	check("fuzz lint", fuzz(lint, true, cfg), "", "")
	check("fuzz not configured", fuzz(disabled, true, config.Default("go")), "", "")
	check("fuzz no changed files", fuzz(noFiles, true, cfg), model.FuzzNoCandidates, "")
	check("fuzz --fuzz=false", fuzz(prepareFailed, false, cfg), model.FuzzDisabled, "")
	check("fuzz --checks=false", fuzz(disabled, true, cfg), model.FuzzDisabled, "")
	check("fuzz --checks=false with reviewer", fuzz(reviewerOnly, true, cfg), model.FuzzDisabled, "")
	check("fuzz prepare failed", fuzz(prepareFailed, true, cfg), model.FuzzNotRun, reasonPrepareFailed)

	check("mutation lint", mutation(lint, cfg), "", "")
	check("mutation not configured", mutation(disabled, config.Default("go")), "", "")
	check("mutation no changed files", mutation(noFiles, cfg), model.MutationNoCandidates, "")
	check("mutation --checks=false", mutation(disabled, cfg), model.MutationNotRun, "initial checks disabled (--checks=false)")
	check("mutation --checks=false with reviewer", mutation(reviewerOnly, cfg), model.MutationNotRun, "initial checks disabled (--checks=false)")
	check("mutation prepare failed", mutation(prepareFailed, cfg), model.MutationNotRun, reasonPrepareFailed)

	check("base tests lint", base(lint, true), "", "")
	check("base tests not requested", base(prepareFailed, false), "", "")
	check("base tests no changed files", base(noFiles, true), model.BaseTestsNoCandidates, "")
	check("base tests prepare failed", base(prepareFailed, true), model.BaseTestsNotRun, reasonPrepareFailed)

	check("impacted lint", impacted(lint, true), "", "")
	check("impacted not requested", impacted(prepareFailed, false), "", "")
	check("impacted no changed files", impacted(noFiles, true), model.ImpactTestsNoCandidates, "")
	check("impacted prepare failed", impacted(prepareFailed, true), model.ImpactTestsNotRun, reasonPrepareFailed)

	// A section a stage already recorded is never overwritten.
	r := &model.Report{Fuzz: &model.FuzzReport{Status: model.FuzzRan}, Mutation: &model.Mutation{Status: model.MutationRan}, BaseTests: &model.BaseTests{Status: model.BaseTestsRan}, Impact: &model.Impact{TestsStatus: model.ImpactTestsRan}}
	recordFuzzSkipped(cfg, prepareFailed, true, r)
	recordMutationSkipped(cfg, prepareFailed, r)
	recordBaseTestsSkipped(prepareFailed, true, r)
	recordImpactedTestsSkipped(prepareFailed, true, r)
	if r.Fuzz.Status != model.FuzzRan || r.Mutation.Status != model.MutationRan || r.BaseTests.Status != model.BaseTestsRan || r.Impact.TestsStatus != model.ImpactTestsRan {
		t.Fatalf("recorded sections were overwritten: %+v %+v %+v %+v", r.Fuzz, r.Mutation, r.BaseTests, r.Impact)
	}
	// Impacted tests need an impact section; without one there is nothing to record into.
	r = &model.Report{}
	recordImpactedTestsSkipped(prepareFailed, true, r)
	if r.Impact != nil {
		t.Fatal("recordImpactedTestsSkipped invented an impact section")
	}
	if skippedReason(stageContext{mode: "review", executed: true}) == "" {
		t.Fatal("an executed run without a section needs a reason")
	}
}

func TestInitialChecksOrder(t *testing.T) {
	got := initialChecks(map[string][]string{"build": {"b"}, "coverage": {"c"}, "test": {"t"}, "generated_test": {"g"}})
	if strings.Join(got, ",") != "test,build" {
		t.Fatalf("initial checks %v, want test,build", got)
	}
	if got := initialChecks(config.Default("go").Commands); strings.Join(got, ",") != "test,typecheck,build" {
		t.Fatalf("Go default initial checks %v", got)
	}
	if got := initialChecks(nil); len(got) != 0 {
		t.Fatalf("no commands gave %v", got)
	}
}
