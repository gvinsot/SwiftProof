package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gvinsot/SwiftProof/app/internal/config"
	"github.com/gvinsot/SwiftProof/app/internal/coverage"
)

// calcFixture is a change that keeps behavior and passes its tests, so a review
// that requests nothing new has nothing to report.
func calcFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	git(t, dir, "init", "-b", "main")
	write(t, dir, "go.mod", "module example.test/calc\n\ngo 1.23\n")
	write(t, dir, "calc.go", "package calc\n\n// Add returns the sum of a and b.\nfunc Add(a, b int) int { return a + b }\n")
	write(t, dir, "calc_test.go", "package calc\n\nimport \"testing\"\n\nfunc TestAdd(t *testing.T) {\n\tif Add(2, 3) != 5 {\n\t\tt.Fatal(\"2+3\")\n\t}\n}\n")
	git(t, dir, "add", ".")
	git(t, dir, "commit", "-m", "baseline")
	git(t, dir, "checkout", "-b", "candidate")
	write(t, dir, "calc.go", "package calc\n\n// Add returns the sum of a and b.\nfunc Add(a, b int) int { return b + a }\n")
	git(t, dir, "add", ".")
	git(t, dir, "commit", "-m", "candidate")
	return dir
}

// The v0.4 skeleton around real sandbox checks: the initial checks run in
// their fixed order under one progress line, coverage follows them, --parallel
// and --deadline are accepted, and a review that requests no new stage adds no
// review request of its own.
func TestDockerReviewSkeletonAroundRealChecks(t *testing.T) {
	image := os.Getenv("SWIFTPROOF_TEST_DOCKER_IMAGE")
	if image == "" {
		t.Skip("set SWIFTPROOF_TEST_DOCKER_IMAGE to a preloaded Go image")
	}
	dir := calcFixture(t)
	cfg := config.Default("go")
	cfg.Sandbox.Image = image
	policy := filepath.Join(t.TempDir(), "policy.json")
	writeReviewerPolicy(t, policy, cfg)
	var out, errOut bytes.Buffer
	code := Run(context.Background(), []string{"review", "--repo", dir, "--config", policy, "--reviewer=false", "--parallel", "2", "--deadline", "15m", "--ci", "--out", "report"}, &out, &errOut, "integration")
	r := readReviewerReport(t, dir)
	if code != 0 {
		t.Fatalf("exit %d, want 0: checks %+v unverified %q\n%s", code, r.Checks, r.Unverified, errOut.String())
	}
	if !strings.Contains(errOut.String(), "Running test, typecheck, build in isolated Docker sandboxes...") {
		t.Fatalf("missing the combined progress line:\n%s", errOut.String())
	}
	if got := strings.Join(checkKinds(r), ","); got != "test,typecheck,build,"+coverage.CommandKey {
		t.Fatalf("check order %s", got)
	}
	for _, c := range r.Checks {
		if c.Status != "PASS" {
			t.Fatalf("check %s %s: %s\n%s", c.ID, c.Kind, c.Status, c.Output)
		}
	}
	if r.Coverage.Status != coverage.StatusMeasured {
		t.Fatalf("coverage %s: %s", r.Coverage.Status, r.Coverage.Reason)
	}
	if r.Fuzz != nil || r.Mutation != nil || r.BaseTests != nil || r.Prepare != nil {
		t.Fatal("a stage that was neither requested nor configured recorded a section")
	}
	if len(r.Divergences) != 0 || len(r.Unverified) != 0 {
		t.Fatalf("unexpected divergences %v or unverified %q", r.Divergences, r.Unverified)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if !strings.HasPrefix(lines[len(lines)-1], "Reports: ") {
		t.Fatalf("the Reports line is not last:\n%s", out.String())
	}
}

// --deadline stops a running check (TIMEOUT through the bounded cleanup path),
// skips the checks that had not started, records the deadline entry, and does
// not by itself make the run an operational failure.
func TestDockerDeadlineStopsRunningCheck(t *testing.T) {
	image := os.Getenv("SWIFTPROOF_TEST_DOCKER_IMAGE")
	if image == "" {
		t.Skip("set SWIFTPROOF_TEST_DOCKER_IMAGE to a preloaded Go image")
	}
	dir := calcFixture(t)
	cfg := config.Default("go")
	cfg.Sandbox.Image = image
	cfg.Commands = map[string][]string{"test": {"sh", "-c", "sleep 120"}, "typecheck": {"go", "vet", "./..."}, "build": {"go", "build", "./..."}}
	policy := filepath.Join(t.TempDir(), "policy.json")
	writeReviewerPolicy(t, policy, cfg)
	// The run started 20 s ago with --deadline 1m: 30 s are kept for the report,
	// so about 10 s remain for execution.
	started := time.Now()
	ctx := withStart(context.Background(), started.Add(-20*time.Second))
	var out, errOut bytes.Buffer
	code := Run(ctx, []string{"review", "--repo", dir, "--config", policy, "--reviewer=false", "--deadline", "1m", "--ci", "--out", "report"}, &out, &errOut, "integration")
	elapsed := time.Since(started)
	r := readReviewerReport(t, dir)
	if code != 2 {
		t.Fatalf("exit %d, want 2: %+v\n%s", code, r.Checks, errOut.String())
	}
	if elapsed > 60*time.Second {
		t.Fatalf("the run took %s after its deadline", elapsed)
	}
	if len(r.Checks) != 3 {
		t.Fatalf("checks %v", checkKinds(r))
	}
	if first := r.Checks[0].Status; first != "TIMEOUT" && first != "SKIPPED" {
		t.Fatalf("the running check ended %s, want TIMEOUT (or SKIPPED when the sandbox had not started)", first)
	}
	for _, c := range r.Checks[1:] {
		if c.Status != "SKIPPED" || !strings.Contains(c.Output, "deadline") {
			t.Fatalf("check %s after the deadline: %s %q", c.Kind, c.Status, c.Output)
		}
	}
	found := false
	for _, u := range r.Unverified {
		found = found || u == deadlineNote
	}
	if !found {
		t.Fatalf("missing deadline entry: %q", r.Unverified)
	}
	for _, c := range r.Checks {
		if c.Status == "ERROR" {
			t.Fatalf("check %s recorded %s", c.ID, c.Status)
		}
	}
}
