package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gvinsot/SwiftProof/internal/config"
	"github.com/gvinsot/SwiftProof/internal/coverage"
	"github.com/gvinsot/SwiftProof/internal/model"
)

func TestValidateOutputRejectsUserSymlink(t *testing.T) {
	root := t.TempDir()
	if err := validateOutput(filepath.Join(root, "new", "report")); err != nil {
		t.Fatalf("normal temporary output: %v", err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(root, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if err := validateOutput(filepath.Join(link, "report")); err == nil {
		t.Fatal("user symlink accepted for output")
	}
}

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-c", "user.name=SwiftProof Test", "-c", "user.email=test@example.invalid", "-c", "commit.gpgsign=false"}, args...)...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v %s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}
func write(t *testing.T, dir, name, data string) {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(data), 0644); err != nil {
		t.Fatal(err)
	}
}
func fixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	git(t, dir, "init", "-b", "main")
	write(t, dir, "go.mod", "module example.test/fixture\n\ngo 1.23\n")
	write(t, dir, "auth.go", "package fixture\n\nfunc Allowed(user string) bool { return user == \"admin\" }\n")
	git(t, dir, "add", ".")
	git(t, dir, "commit", "-m", "baseline")
	git(t, dir, "checkout", "-b", "candidate")
	write(t, dir, "auth.go", "package fixture\n\nfunc Allowed(user string) bool { return true }\n")
	git(t, dir, "add", ".")
	git(t, dir, "commit", "-m", "candidate")
	return dir
}
func TestLintEndToEndAndRender(t *testing.T) {
	dir := fixture(t)
	var out, errOut bytes.Buffer
	code := Run(context.Background(), []string{"lint", "--repo", dir, "--base", "main", "--out", "reports"}, &out, &errOut, "test")
	if code != 0 {
		t.Fatalf("code %d: %s", code, errOut.String())
	}
	b, err := os.ReadFile(filepath.Join(dir, "reports", "confidence-report.json"))
	if err != nil {
		t.Fatal(err)
	}
	var r model.Report
	if err = json.Unmarshal(b, &r); err != nil {
		t.Fatal(err)
	}
	if len(r.Change.Files) != 1 || r.Change.HeadCommit == r.Change.BaseCommit {
		t.Fatalf("wrong change: %+v", r.Change)
	}
	if len(r.Checks) != 0 {
		t.Fatal("lint executed repository code")
	}
	if !strings.Contains(out.String(), "Focused review") {
		t.Fatal(out.String())
	}
	// Nothing ran, so nothing may be claimed about changed-line execution.
	if r.Coverage.Status != coverage.StatusNotConfigured {
		t.Fatalf("lint reported coverage status %q, want %q: %+v", r.Coverage.Status, coverage.StatusNotConfigured, r.Coverage)
	}
	if got := coverageSignals(r); len(got) != 0 {
		t.Fatalf("absent coverage data reported as uncovered: %+v", got)
	}
	if got := coverageCaveats(r); len(got) != 0 {
		t.Fatalf("unconfigured coverage contributed to unverified: %q", got)
	}
	if !strings.Contains(out.String(), notMeasuredLine) {
		t.Fatalf("lint stdout omitted the not-measured statement: %s", out.String())
	}
	assertNotConfiguredMarkdown(t, filepath.Join(dir, "reports", "CONFIDENCE_REPORT.md"))
	code = Run(context.Background(), []string{"report", "--input", filepath.Join(dir, "reports", "confidence-report.json"), "--out", filepath.Join(dir, "rendered")}, &out, &errOut, "test")
	if code != 0 {
		t.Fatalf("render code %d: %s", code, errOut.String())
	}
	md, err := os.ReadFile(filepath.Join(dir, "rendered", "CONFIDENCE_REPORT.md"))
	if err != nil || len(md) == 0 {
		t.Fatalf("missing markdown: %v", err)
	}
	assertNotConfiguredMarkdown(t, filepath.Join(dir, "rendered", "CONFIDENCE_REPORT.md"))
}
func TestCandidateCannotReplacePolicy(t *testing.T) {
	dir := fixture(t)
	write(t, dir, config.Filename, `{"version":999,"sandbox":{"network":true}}`)
	git(t, dir, "add", ".")
	git(t, dir, "commit", "-m", "untrusted policy")
	var out, errOut bytes.Buffer
	if code := Run(context.Background(), []string{"lint", "--repo", dir}, &out, &errOut, "test"); code != 0 {
		t.Fatalf("candidate policy was loaded: %d %s", code, errOut.String())
	}
	if code := Run(context.Background(), []string{"lint", "--repo", dir, "--config", filepath.Join(dir, config.Filename)}, &out, &errOut, "test"); code != 3 {
		t.Fatalf("explicit invalid policy code %d", code)
	}
}
func TestInitNeverOverwrites(t *testing.T) {
	dir := t.TempDir()
	var out, errOut bytes.Buffer
	args := []string{"init", "--repo", dir, "--language", "go"}
	if code := Run(context.Background(), args, &out, &errOut, "test"); code != 0 {
		t.Fatal(errOut.String())
	}
	first, _ := os.ReadFile(filepath.Join(dir, config.Filename))
	if code := Run(context.Background(), args, &out, &errOut, "test"); code != 3 {
		t.Fatalf("overwrite returned %d", code)
	}
	last, _ := os.ReadFile(filepath.Join(dir, config.Filename))
	if !bytes.Equal(first, last) {
		t.Fatal("config changed")
	}
}
func TestExplicitSkipReturnsHumanReviewInCI(t *testing.T) {
	dir := fixture(t)
	var out, errOut bytes.Buffer
	code := Run(context.Background(), []string{"review", "main..HEAD", "--repo", dir, "--checks=false", "--ci"}, &out, &errOut, "test")
	if code != 2 {
		t.Fatalf("code %d: %s", code, errOut.String())
	}
}
func TestRenderRevalidatesSavedReproducedClaims(t *testing.T) {
	dir := t.TempDir()
	r := model.Report{Version: 1, ExitCode: 1, Hypotheses: []model.Hypothesis{{ID: "fake", Title: "Unsubstantiated", Severity: "high", Status: "REPRODUCED", EvidenceIDs: []string{"missing"}}}}
	r.ReproducedIssues = append(r.ReproducedIssues, r.Hypotheses[0])
	data, _ := json.Marshal(r)
	input := filepath.Join(dir, "original.json")
	if err := os.WriteFile(input, data, 0600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	output := filepath.Join(dir, "rendered")
	if code := Run(context.Background(), []string{"report", "--input", input, "--out", output}, &out, &errOut, "test"); code != 0 {
		t.Fatalf("render: %d %s", code, errOut.String())
	}
	data, err := os.ReadFile(filepath.Join(output, "confidence-report.json"))
	if err != nil {
		t.Fatal(err)
	}
	var saved model.Report
	if err := json.Unmarshal(data, &saved); err != nil {
		t.Fatal(err)
	}
	if len(saved.ReproducedIssues) != 0 || saved.Hypotheses[0].Status != "UNVERIFIED" {
		t.Fatal("saved model claim bypassed evidence validation")
	}
}

func TestInvalidArguments(t *testing.T) {
	for _, args := range [][]string{{"wat"}, {"lint", "--format", "html"}, {"review", "a..b..c"}, {"init", "--language", "brainfuck"}, {"report", "unexpected"}} {
		var out bytes.Buffer
		if code := Run(context.Background(), args, &out, &out, "test"); code != 3 {
			t.Errorf("%v returned %d: %s", args, code, out.String())
		}
	}
}

// The exact sentences the CLI and the Markdown report owe a reader when no
// changed line was resolved. They are asserted verbatim because an absent
// measurement must never be worded as a not-executed claim.
const (
	notMeasuredLine     = "Changed-line execution: not measured."
	notConfiguredReport = "No coverage command is configured, so changed-line execution was not measured."
	notMeasuredCaveat   = "Changed-line execution was not measured:"
	didNotRun           = "the coverage run did not complete ("
)

// coveragePolicy is a trusted policy that configures a test command and a
// coverage command. Trusted policy rejects an empty sandbox image, so the image
// instead names one that can never resolve: the coverage run is recorded and
// reported without any repository code executing and without a coverage profile
// ever reaching the host, whether or not Docker is installed.
func coveragePolicy(t *testing.T) string {
	t.Helper()
	cfg := config.Default("go")
	cfg.Sandbox.Image = "swiftproof.invalid/absent:test-only"
	cfg.Commands = map[string][]string{
		"test":              {"go", "test", "./..."},
		coverage.CommandKey: {"go", "test", "-covermode=count", "-coverprofile=" + coverage.Placeholder, "./..."},
	}
	path := filepath.Join(t.TempDir(), "policy.json")
	writeReviewerPolicy(t, path, cfg)
	return path
}

func coverageSignals(r model.Report) []model.Signal {
	var out []model.Signal
	for _, s := range r.Signals {
		if s.Kind == coverage.Kind {
			out = append(out, s)
		}
	}
	return out
}
func coverageCaveats(r model.Report) []string {
	var out []string
	for _, u := range r.Unverified {
		if strings.HasPrefix(u, notMeasuredCaveat) {
			out = append(out, u)
		}
	}
	return out
}
func checkKinds(r model.Report) []string {
	kinds := make([]string, len(r.Checks))
	for i, c := range r.Checks {
		kinds[i] = c.Kind
	}
	return kinds
}
func assertNotConfiguredMarkdown(t *testing.T, path string) {
	t.Helper()
	md, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(md), notConfiguredReport); n != 1 {
		t.Fatalf("unconfigured coverage stated %d times in %s, want exactly once:\n%s", n, path, md)
	}
	if strings.Contains(string(md), "not executed") {
		t.Fatalf("absent coverage data reported as not executed in %s:\n%s", path, md)
	}
}

// Coverage is an addition to the configured checks, not a replacement, and it
// runs after them so the shared runtime budget starves the measurement first.
func TestCoverageRunsLastAndOnlyWithChecks(t *testing.T) {
	dir := fixture(t)
	var out, errOut bytes.Buffer
	code := Run(context.Background(), []string{"review", "--repo", dir, "--config", coveragePolicy(t), "--out", "report"}, &out, &errOut, "test")
	if code == 3 {
		t.Fatalf("coverage policy was rejected: %s", errOut.String())
	}
	r := readReviewerReport(t, dir)
	kinds := checkKinds(r)
	if len(kinds) == 0 || kinds[len(kinds)-1] != coverage.CommandKey {
		t.Fatalf("coverage did not run last: %v", kinds)
	}
	counts := map[string]int{}
	for _, kind := range kinds {
		counts[kind]++
	}
	if counts["test"] != 1 {
		t.Fatalf("coverage replaced the configured test command: %v", kinds)
	}
	if counts[coverage.CommandKey] != 1 {
		t.Fatalf("coverage ran %d times: %v", counts[coverage.CommandKey], kinds)
	}
	if r.Coverage.Status != coverage.StatusNotMeasured {
		t.Fatalf("coverage status %q, want %q: %+v", r.Coverage.Status, coverage.StatusNotMeasured, r.Coverage)
	}
	if !strings.HasPrefix(r.Coverage.Reason, didNotRun) {
		t.Fatalf("reason %q does not start with %q", r.Coverage.Reason, didNotRun)
	}
	if got := coverageCaveats(r); len(got) != 1 {
		t.Fatalf("an unmeasured run must be declared unverified exactly once, got %q", got)
	}
	if got := coverageSignals(r); len(got) != 0 {
		t.Fatalf("absent coverage data reported as uncovered: %+v", got)
	}
	if r.Coverage.AddedLines != 0 || r.Coverage.NotExecutedLines != 0 {
		t.Fatalf("an unmeasured run counted lines: %+v", r.Coverage)
	}
}

// Lint never executes repository code, so a configured coverage command must
// not turn it into an execution.
func TestCoverageNeverRunsInLint(t *testing.T) {
	dir := fixture(t)
	var out, errOut bytes.Buffer
	if code := Run(context.Background(), []string{"lint", "--repo", dir, "--config", coveragePolicy(t), "--out", "report"}, &out, &errOut, "test"); code != 0 {
		t.Fatalf("code %d: %s", code, errOut.String())
	}
	r := readReviewerReport(t, dir)
	if len(r.Checks) != 0 {
		t.Fatalf("lint executed repository code: %v", checkKinds(r))
	}
	if r.Coverage.Status != coverage.StatusNotConfigured {
		t.Fatalf("lint reported coverage status %q, want %q: %+v", r.Coverage.Status, coverage.StatusNotConfigured, r.Coverage)
	}
	if got := coverageSignals(r); len(got) != 0 {
		t.Fatalf("lint produced coverage signals without running anything: %+v", got)
	}
	if got := coverageCaveats(r); len(got) != 0 {
		t.Fatalf("lint recorded a measurement caveat: %q", got)
	}
}

// Disabled checks disable the measurement with them: nothing ran, so the report
// stays at "not configured" rather than inventing an unmeasured run.
func TestCoverageConfiguredButChecksDisabled(t *testing.T) {
	dir := fixture(t)
	var out, errOut bytes.Buffer
	if code := Run(context.Background(), []string{"review", "--repo", dir, "--config", coveragePolicy(t), "--checks=false", "--out", "report"}, &out, &errOut, "test"); code != 0 {
		t.Fatalf("code %d: %s", code, errOut.String())
	}
	r := readReviewerReport(t, dir)
	for _, kind := range checkKinds(r) {
		if kind == coverage.CommandKey {
			t.Fatalf("coverage ran with checks disabled: %v", checkKinds(r))
		}
	}
	if r.Coverage.Status != coverage.StatusNotConfigured {
		t.Fatalf("coverage status %q, want %q: %+v", r.Coverage.Status, coverage.StatusNotConfigured, r.Coverage)
	}
	if got := coverageSignals(r); len(got) != 0 {
		t.Fatalf("absent coverage data reported as uncovered: %+v", got)
	}
}

// Every run states what was measured on stdout, including the runs that
// measured nothing.
func TestStdoutReportsChangedLineExecution(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{name: "coverage command did not run", args: []string{"review"}},
		{name: "no coverage command configured", args: []string{"lint"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := fixture(t)
			var out, errOut bytes.Buffer
			args := append(append([]string{}, tc.args...), "--repo", dir, "--config", coveragePolicy(t), "--out", "report")
			if code := Run(context.Background(), args, &out, &errOut, "test"); code == 3 {
				t.Fatalf("coverage policy was rejected: %s", errOut.String())
			}
			if !strings.Contains(out.String(), notMeasuredLine) {
				t.Fatalf("stdout omitted %q: %s", notMeasuredLine, out.String())
			}
			if strings.Contains(out.String(), "not executed,") {
				t.Fatalf("absent coverage data reported as not executed: %s", out.String())
			}
		})
	}
}
