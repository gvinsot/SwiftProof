package coverage

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/gvinsot/SwiftProof/app/internal/model"
)

const module = "example.com/m"

func mustParse(t *testing.T, rows ...string) *Profile {
	t.Helper()
	p, err := ParseGoProfile([]byte("mode: count\n" + strings.Join(rows, "\n") + "\n"))
	if err != nil {
		t.Fatalf("fixture profile: %v", err)
	}
	return p
}

func file(path string, added []int, removed []int) model.ChangedFile {
	f := model.ChangedFile{Path: path, Status: "M"}
	var lines []model.DiffLine
	for _, l := range added {
		lines = append(lines, model.DiffLine{Kind: "add", NewLine: l, Content: "x"})
	}
	for _, l := range removed {
		lines = append(lines, model.DiffLine{Kind: "delete", OldLine: l, Content: "y"})
	}
	lines = append(lines, model.DiffLine{Kind: "context", NewLine: 999, OldLine: 999})
	f.Hunks = []model.Hunk{{Lines: lines}}
	return f
}

func pass(module string) Run {
	return Run{CheckID: "check-4", Status: "PASS", Command: []string{"go", "test", "-coverprofile=/tmp/swiftproof-coverage.out", "./..."}, SHA256: strings.Repeat("a", 64), Module: module}
}

// Every added line lands in exactly one of the four states, and removed lines
// are reported beside that sum rather than inside it.
func TestFourStateResolution(t *testing.T) {
	p := mustParse(t,
		module+"/internal/a/a.go:10.20,14.3 2 7", // executed
		module+"/internal/a/a.go:20.20,24.3 2 0", // not executed
	)
	change := model.Change{Files: []model.ChangedFile{
		file("internal/a/a.go", []int{1, 11, 12, 21, 22, 40}, []int{5, 6}),
		file("internal/b/b.go", []int{3}, nil),
	}}
	result := Analyze(p, pass(module), change)
	got := result.Report()
	if got.Status != StatusMeasured {
		t.Fatalf("status %q", got.Status)
	}
	if got.ExecutedLines != 2 || got.NotExecutedLines != 2 || got.NoBlockLines != 2 || got.NotMeasuredLines != 1 {
		t.Fatalf("states: executed=%d not_executed=%d no_block=%d not_measured=%d", got.ExecutedLines, got.NotExecutedLines, got.NoBlockLines, got.NotMeasuredLines)
	}
	if sum := got.ExecutedLines + got.NotExecutedLines + got.NoBlockLines + got.NotMeasuredLines; sum != got.AddedLines {
		t.Fatalf("invariant broken: %d states for %d added lines", sum, got.AddedLines)
	}
	if got.RemovedLines != 2 {
		t.Fatalf("removed lines %d", got.RemovedLines)
	}
	for _, f := range got.Files {
		if f.ExecutedLines+f.NotExecutedLines+f.NoBlockLines+f.NotMeasuredLines != f.AddedLines {
			t.Fatalf("per-file invariant broken for %s: %+v", f.Path, f)
		}
	}
	if n := len(result.Signals()); n != 1 {
		t.Fatalf("expected one contiguous uncovered range, got %d", n)
	}
	s := result.Signals()[0]
	if s.Kind != Kind || s.Path != "internal/a/a.go" || s.Line != 21 || s.EndLine != 22 || s.Side != "new" {
		t.Fatalf("signal location: %+v", s)
	}
}

// Any containing block that ran makes the line executed. The tie-break is
// one-directional so it can only reduce the number of claims made.
func TestLineInTwoBlocksResolvesToExecuted(t *testing.T) {
	p := mustParse(t,
		module+"/a.go:1.1,9.1 3 0",
		module+"/a.go:4.10,6.3 1 2",
	)
	result := Analyze(p, pass(module), model.Change{Files: []model.ChangedFile{file("a.go", []int{5}, nil)}})
	if got := result.Report(); got.ExecutedLines != 1 || got.NotExecutedLines != 0 {
		t.Fatalf("overlapping blocks resolved as not executed: %+v", got)
	}
	if len(result.Signals()) != 0 {
		t.Fatal("a line inside an executed block produced a signal")
	}
}

// Absent coverage data must never render as a not-executed claim.
func TestUnmappedFileIsNotMeasuredNotUncovered(t *testing.T) {
	p := mustParse(t, module+"/other.go:1.1,2.2 1 0")
	for _, run := range []Run{pass(module), pass("forged.example/other")} {
		result := Analyze(p, run, model.Change{Files: []model.ChangedFile{file("a.go", []int{1, 2, 3}, nil)}})
		got := result.Report()
		if got.NotMeasuredLines != 3 || got.NotExecutedLines != 0 {
			t.Fatalf("module %q: absent coverage data reported as uncovered: %+v", run.Module, got)
		}
		if len(result.Signals()) != 0 {
			t.Fatalf("module %q: unmapped file produced a signal", run.Module)
		}
		if got.Files[0].Status != StatusNotMeasured {
			t.Fatalf("module %q: file status %q", run.Module, got.Files[0].Status)
		}
	}
}

// A sibling block in the same package proves nothing about this file.
func TestZeroBlockFileIsNotMeasured(t *testing.T) {
	p := mustParse(t, module+"/internal/a/a.go:10.1,12.2 1 4")
	result := Analyze(p, pass(module), model.Change{Files: []model.ChangedFile{file("internal/a/doc.go", []int{1, 2}, nil)}})
	got := result.Report()
	if got.NotMeasuredLines != 2 || got.NoBlockLines != 0 {
		t.Fatalf("a file with no block of its own was treated as instrumented: %+v", got)
	}
	if len(result.Signals()) != 0 {
		t.Fatal("unmeasured file produced a signal")
	}
}

func TestDeletedLinesTestFilesAndNonGoExcluded(t *testing.T) {
	p := mustParse(t, module+"/a.go:1.1,9.9 1 0")
	deleted := model.ChangedFile{Path: "gone.go", Status: "D", Hunks: []model.Hunk{{Lines: []model.DiffLine{{Kind: "delete", OldLine: 1}}}}}
	binary := model.ChangedFile{Path: "image.go", Status: "M", Binary: true, Hunks: []model.Hunk{{Lines: []model.DiffLine{{Kind: "add", NewLine: 1}}}}}
	change := model.Change{Files: []model.ChangedFile{
		file("a_test.go", []int{1, 2}, nil),
		file("script.sh", []int{1}, nil),
		file("notes.md", []int{1}, []int{9}),
		deleted, binary,
		file("a.go", []int{1}, []int{4, 5}),
	}}
	got := Analyze(p, pass(module), change).Report()
	if got.AddedLines != 1 || got.ExecutedLines != 0 || got.NotExecutedLines != 1 {
		t.Fatalf("out-of-scope files contributed to the counters: %+v", got)
	}
	if got.RemovedLines != 2 {
		t.Fatalf("removed lines should count only in-scope files: %d", got.RemovedLines)
	}
	if len(got.Files) != 1 || got.Files[0].Path != "a.go" {
		t.Fatalf("reported files: %+v", got.Files)
	}
}

// The profile records the candidate revision, so the new path is the key.
func TestRenamedFileUsesNewPath(t *testing.T) {
	p := mustParse(t, module+"/new.go:1.1,3.3 1 0")
	f := file("new.go", []int{2}, nil)
	f.Status, f.OldPath = "R", "old.go"
	result := Analyze(p, pass(module), model.Change{Files: []model.ChangedFile{f}})
	if got := result.Report(); got.NotExecutedLines != 1 || got.NotMeasuredLines != 0 {
		t.Fatalf("renamed file not matched by its new path: %+v", got)
	}
}

func TestContiguousRunsAndCaps(t *testing.T) {
	var added []int
	rows := []string{}
	for i := 0; i < maxRunsPerFile+3; i++ {
		line := 1 + i*10
		added = append(added, line, line+1)
		rows = append(rows, module+"/a.go:"+strconv.Itoa(line)+".1,"+strconv.Itoa(line+1)+".9 1 0")
	}
	result := Analyze(mustParse(t, rows...), pass(module), model.Change{Files: []model.ChangedFile{file("a.go", added, nil)}})
	signals := result.Signals()
	if len(signals) != maxRunsPerFile+1 {
		t.Fatalf("expected %d ranges plus one overflow, got %d", maxRunsPerFile, len(signals))
	}
	for _, s := range signals[:maxRunsPerFile] {
		if s.EndLine != s.Line+1 {
			t.Fatalf("adjacent lines were not merged into one range: %+v", s)
		}
	}
	overflow := signals[maxRunsPerFile]
	if !strings.Contains(overflow.Summary, "Further added lines") {
		t.Fatalf("overflow summary: %q", overflow.Summary)
	}
	if !strings.Contains(overflow.Evidence, "6 further new-side lines") {
		t.Fatalf("overflow evidence does not count the folded lines: %q", overflow.Evidence)
	}
	if got := result.Report().NotExecutedLines; got != len(added) {
		t.Fatalf("capping ranges changed the counters: %d", got)
	}
}

func TestSeverityFollowsCheckStatus(t *testing.T) {
	p := mustParse(t, module+"/a.go:1.1,3.3 1 0")
	change := model.Change{Files: []model.ChangedFile{file("a.go", []int{2}, nil)}}
	passing := Analyze(p, pass(module), change).Signals()[0]
	if passing.Severity != "medium" || !strings.Contains(passing.Summary, "not executed by any instrumented package") {
		t.Fatalf("passing run: %+v", passing)
	}
	if strings.Contains(passing.Evidence, "did not pass") {
		t.Fatal("passing run carries the stopped-early caveat")
	}
	failing := pass(module)
	failing.Status = "FAIL"
	stopped := Analyze(p, failing, change).Signals()[0]
	if stopped.Severity != "low" {
		t.Fatalf("a measurement from a run that did not pass kept severity %q", stopped.Severity)
	}
	if !strings.Contains(stopped.Summary, "before the coverage run stopped") || !strings.Contains(stopped.Evidence, "may lie after the point where the run stopped") {
		t.Fatalf("stopped-early wording missing: %+v", stopped)
	}
}

func TestModulePath(t *testing.T) {
	dir := t.TempDir()
	write := func(body string) { os.WriteFile(filepath.Join(dir, "go.mod"), []byte(body), 0600) }
	write("// a comment\n\nmodule example.com/m // trailing\n\ngo 1.23.0\n")
	got, err := ModulePath(dir)
	if err != nil || got != "example.com/m" {
		t.Fatalf("module path %q err %v", got, err)
	}
	for name, body := range map[string]string{
		"absent directive": "go 1.23.0\n",
		"two directives":   "module a.example/one\nmodule b.example/two\n",
		"empty":            "",
	} {
		write(body)
		if _, err := ModulePath(dir); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	if err := os.Remove(filepath.Join(dir, "go.mod")); err != nil {
		t.Fatal(err)
	}
	if _, err := ModulePath(dir); err != ErrModulePath {
		t.Fatalf("missing go.mod: %v", err)
	}
}

// A go.work module in a subdirectory keys its files by its own module path and
// the path relative to its directory; files outside every module stay unmeasured.
func TestWorkspaceModuleKeys(t *testing.T) {
	p := mustParse(t,
		"example.com/app/internal/a/a.go:10.20,14.3 2 7",
		"example.com/app/internal/a/a.go:20.20,24.3 2 0",
	)
	run := pass("")
	run.Workspace = map[string]string{"app": "example.com/app"}
	change := model.Change{Files: []model.ChangedFile{
		file("app/internal/a/a.go", []int{11, 21}, nil),
		file("web/tool.go", []int{3}, nil),
	}}
	got := Analyze(p, run, change).Report()
	if got.ExecutedLines != 1 || got.NotExecutedLines != 1 || got.NotMeasuredLines != 1 {
		t.Fatalf("states: executed=%d not_executed=%d not_measured=%d", got.ExecutedLines, got.NotExecutedLines, got.NotMeasuredLines)
	}
	nested := Run{Module: "example.com/root", Workspace: map[string]string{"app": "example.com/app", "app/sub": "example.com/sub"}}
	for path, want := range map[string]string{"main.go": "example.com/root/main.go", "app/x.go": "example.com/app/x.go", "app/sub/y.go": "example.com/sub/y.go", "application/z.go": "example.com/root/application/z.go"} {
		if key := nested.profileKey(path); key != want {
			t.Fatalf("%s keyed as %q, want %q", path, key, want)
		}
	}
}

func TestModules(t *testing.T) {
	dir := t.TempDir()
	put := func(name, body string) {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, name)), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	put("app/go.mod", "module example.com/app\n")
	put("tools/go.mod", "module example.com/tools\n")
	if _, _, err := Modules(dir); err != ErrModulePath {
		t.Fatalf("no go.mod nor go.work: %v", err)
	}
	put("go.work", "go 1.23.0\n\nuse ./app // the product\nuse (\n\t\"./tools\"\n)\n")
	root, workspace, err := Modules(dir)
	if err != nil || root != "" || len(workspace) != 2 || workspace["app"] != "example.com/app" || workspace["tools"] != "example.com/tools" {
		t.Fatalf("root %q workspace %v err %v", root, workspace, err)
	}
	put("go.mod", "module example.com/root\n")
	put("go.work", "go 1.23.0\nuse (\n\t.\n\t./app\n)\n")
	root, workspace, err = Modules(dir)
	if err != nil || root != "example.com/root" || len(workspace) != 1 {
		t.Fatalf("root %q workspace %v err %v", root, workspace, err)
	}
	for name, body := range map[string]string{
		"escaping":      "use ../outside\n",
		"absolute":      "use /abs\n",
		"missing":       "use ./absent\n",
		"unterminated":  "use (\n./app\n",
		"two per line":  "use (\n./app ./tools\n)\n",
		"windows drive": "use C:/app\n",
	} {
		put("go.work", body)
		if _, _, err := Modules(dir); err != ErrModulePath {
			t.Fatalf("%s go.work accepted: %v", name, err)
		}
	}
}

// Coverage may add sentences to an existing signal. It never changes what that
// signal claims, and an unmeasured file keeps its original wording.
func TestRequalifyOnlyTouchesMeasuredFiles(t *testing.T) {
	const original = "No changed test file shares this source directory or filename stem. Existing test coverage has not been measured"
	signals := []model.Signal{
		{Kind: "no_test_change", Path: "a.go", Severity: "low", Summary: "No nearby test file changed", Evidence: original},
		{Kind: "no_test_change", Path: "doc.go", Severity: "low", Summary: "No nearby test file changed", Evidence: original},
		{Kind: "auth_change", Path: "a.go", Severity: "high", Summary: "Authentication or authorization logic changed", Evidence: original},
	}
	p := mustParse(t, module+"/a.go:1.1,3.3 1 5", module+"/a.go:10.1,12.3 1 0")
	change := model.Change{Files: []model.ChangedFile{file("a.go", []int{2, 11}, nil), file("doc.go", []int{1}, nil)}}
	out := Requalify(signals, Analyze(p, pass(module), change))
	if strings.Contains(out[0].Evidence, "has not been measured") {
		t.Fatalf("measured file kept the unmeasured wording: %q", out[0].Evidence)
	}
	if !strings.Contains(out[0].Evidence, "of 2 added lines inside an instrumented block, 1 were executed at least once") {
		t.Fatalf("requalified evidence: %q", out[0].Evidence)
	}
	if out[0].Kind != "no_test_change" || out[0].Severity != "low" || out[0].Summary != "No nearby test file changed" {
		t.Fatalf("requalification changed the claim: %+v", out[0])
	}
	if out[1].Evidence != original {
		t.Fatalf("unmeasured file was requalified: %q", out[1].Evidence)
	}
	if out[2].Evidence != original {
		t.Fatalf("a signal of another kind was rewritten: %q", out[2].Evidence)
	}
	if got := Requalify(signals, NotMeasured("nope")); got[0].Evidence != original {
		t.Fatalf("an unmeasured run requalified a signal: %q", got[0].Evidence)
	}
}

func TestNotMeasuredReasonsAreExact(t *testing.T) {
	want := []string{
		"no coverage profile was emitted by the coverage command",
		"the coverage profile did not fit in the sandbox payload budget or was cut short; raise sandbox.max_output_bytes",
		"the coverage payload channel carried unexpected output",
		"the coverage profile is not a Go coverage profile; only Go coverage profiles are supported in this version",
		"the coverage profile exceeded the parser bound of 200000 blocks",
		"the module path could not be read from go.mod or go.work in the candidate snapshot",
		"the coverage profile could not be retained as evidence",
	}
	got := []string{ErrNoProfile.Error(), ErrTruncated.Error(), ErrPolluted.Error(), ErrNotGo.Error(), ErrBlockLimit.Error(), ErrModulePath.Error(), ErrArtifact.Error()}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("reason %d:\n got %q\nwant %q", i, got[i], want[i])
		}
	}
	result := NotMeasured(ErrNoProfile.Error())
	if result.Status() != StatusNotMeasured || len(result.Signals()) != 0 || result.Report().Files == nil {
		t.Fatalf("not-measured result: %+v", result.Report())
	}
	if NotConfigured().Status != StatusNotConfigured || NotConfigured().Note != Note {
		t.Fatal("not-configured result")
	}
}

// Executed means the line ran. It never means tested, verified or correct.
func TestNoOverstatingVocabulary(t *testing.T) {
	banned := []string{"tested", "verified", "proven", "proves", "guarantee", "%", "is correct", "is safe", "confidence"}
	p := mustParse(t, module+"/a.go:1.1,3.3 1 0")
	change := model.Change{Files: []model.ChangedFile{file("a.go", []int{2}, nil)}}
	texts := []string{Note, summaryPassed, summaryStopped, summaryOverflowPassed, summaryOverflowStopped}
	for _, run := range []string{"PASS", "FAIL"} {
		r := pass(module)
		r.Status = run
		for _, s := range Analyze(p, r, change).Signals() {
			texts = append(texts, s.Summary, s.Evidence)
		}
	}
	texts = append(texts, Requalify([]model.Signal{{Kind: "no_test_change", Path: "a.go"}}, Analyze(p, pass(module), change))[0].Evidence)
	for _, text := range texts {
		for _, word := range banned {
			if strings.Contains(strings.ToLower(text), word) {
				t.Fatalf("overstating vocabulary %q in: %s", word, text)
			}
		}
		if !strings.Contains(text, "executed") && !strings.Contains(text, "Executed") {
			t.Fatalf("text makes a claim without naming execution: %s", text)
		}
	}
}
