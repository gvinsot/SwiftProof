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
	"github.com/gvinsot/SwiftProof/internal/model"
)

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
	code = Run(context.Background(), []string{"report", "--input", filepath.Join(dir, "reports", "confidence-report.json"), "--out", filepath.Join(dir, "rendered")}, &out, &errOut, "test")
	if code != 0 {
		t.Fatalf("render code %d: %s", code, errOut.String())
	}
	md, err := os.ReadFile(filepath.Join(dir, "rendered", "CONFIDENCE_REPORT.md"))
	if err != nil || len(md) == 0 {
		t.Fatalf("missing markdown: %v", err)
	}
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
