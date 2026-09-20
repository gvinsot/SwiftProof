package coverage

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/gvinsot/SwiftProof/internal/model"
)

// Report statuses. A measurement is only ever "measured" when every condition
// of the global gate held; every other outcome is "not measured".
const (
	StatusNotConfigured = "not_configured"
	StatusNotMeasured   = "not_measured"
	StatusMeasured      = "measured"
)

// Kind is the signal kind emitted for added lines a recorded run did not execute.
const Kind = "uncovered_change"

// Note states what the measurement does and does not establish. It is copied
// into every report, including reports where nothing was measured.
const Note = "Executed means the line ran at least once during the recorded run. The coverage profile is produced by the test suite of the candidate revision and is recorded as a report, not as proof. It is not evidence that behavior is asserted, correct or safe. Deleted lines, test files and non-Go files are outside this measurement. Verdicts are block-granular: a line inside an instrumented block carries the count of that block, including lines that hold no statement of their own. Execution is measured per instrumented package; a line executed only through the tests of another package counts as not executed unless the coverage command sets -coverpkg. If the run did not pass, a line reported as not executed may lie after the point where the run stopped."

const (
	summaryPassed          = "Added lines were not executed by any instrumented package in the coverage run"
	summaryStopped         = "Added lines were not executed before the coverage run stopped; the run did not pass"
	summaryOverflowPassed  = "Further added lines in this file were not executed by the recorded coverage run"
	summaryOverflowStopped = "Further added lines in this file were not executed before the coverage run stopped"

	evidenceRun      = "Go coverage profile recorded in %s reports execution count 0 for every instrumented block containing new-side lines %d-%d. Measured command: %s. The profile is produced by the test suite of the candidate revision and is recorded as a report, not as proof. Executed means the line ran at least once during that run; it is not evidence that behavior is asserted, correct or safe."
	evidenceOverflow = "Go coverage profile recorded in %s reports execution count 0 for %d further new-side lines between %d and %d in this file, beyond the %d ranges reported individually. Measured command: %s. The profile is produced by the test suite of the candidate revision and is recorded as a report, not as proof. Executed means the line ran at least once during that run; it is not evidence that behavior is asserted, correct or safe."
	evidenceStopped  = " The run that produced this profile did not pass, so a line reported as not executed may lie after the point where the run stopped."

	// Requalified evidence of an existing no_test_change signal. Its kind,
	// severity and summary never change, and an unmeasured file keeps the
	// original wording byte for byte.
	evidenceRequalified = "No changed test file shares this source directory or filename stem. Changed-line execution was measured for this file in %s: of %d added lines inside an instrumented block, %d were executed at least once. Executing a line is not asserting its behavior."
)

const (
	maxRunsPerFile   = 25
	maxSignals       = 200
	maxReportedFiles = 500
	maxGoModBytes    = 1 << 20
)

// Run describes the recorded sandbox execution a measurement is derived from.
type Run struct {
	CheckID string
	Status  string
	Command []string
	SHA256  string
	Module  string
}

// Result is a completed measurement. It can add signals and add sentences; it
// never deletes a signal, lowers a severity or supports a dismissal, because
// the profile is written by the candidate revision's own test suite.
type Result struct {
	coverage model.Coverage
	signals  []model.Signal
	byPath   map[string]model.CoverageFile
}

// Report returns the serializable measurement.
func (r Result) Report() model.Coverage { return r.coverage }

// Status is one of the status constants.
func (r Result) Status() string { return r.coverage.Status }

// Signals returns the uncovered_change signals, in file then ascending line order.
func (r Result) Signals() []model.Signal { return append([]model.Signal(nil), r.signals...) }

// NotMeasured records why no changed line could be resolved. It never produces
// a signal: there is no code path from missing data to a not-executed claim.
func NotMeasured(reason string) Result {
	return Result{
		coverage: model.Coverage{Status: StatusNotMeasured, Reason: reason, Files: []model.CoverageFile{}, Note: Note},
		byPath:   map[string]model.CoverageFile{},
	}
}

// NotConfigured is the state of a repository whose trusted policy has no
// coverage command: nothing ran and nothing is claimed.
func NotConfigured() model.Coverage {
	return model.Coverage{Status: StatusNotConfigured, Files: []model.CoverageFile{}, Note: Note}
}

// Analyze resolves every added new-side line of every changed non-test Go file
// into exactly one of four states. Files are matched by building the expected
// profile key from the module path and the diff and asking the profile a yes/no
// question; a container-supplied string is never mapped back onto a repository
// path, so a mismatched or forged profile misses and yields "not measured"
// instead of a confident claim about the wrong file.
func Analyze(p *Profile, run Run, change model.Change) Result {
	blocks := map[string][]Block{}
	for _, b := range p.Blocks {
		blocks[b.File] = append(blocks[b.File], b)
	}
	severity := "low"
	summary, overflowSummary := summaryStopped, summaryOverflowStopped
	if run.Status == "PASS" {
		severity, summary, overflowSummary = "medium", summaryPassed, summaryOverflowPassed
	}
	command := strings.Join(run.Command, " ")
	result := Result{
		coverage: model.Coverage{Status: StatusMeasured, CheckID: run.CheckID, ProfileSHA256: run.SHA256, Command: run.Command, Files: []model.CoverageFile{}, Note: Note},
		byPath:   map[string]model.CoverageFile{},
	}
	for _, f := range change.Files {
		if !inScope(f) {
			continue
		}
		added, removed := changedLines(f)
		result.coverage.RemovedLines += removed
		if len(added) == 0 {
			continue
		}
		file := model.CoverageFile{Path: f.Path, Status: StatusMeasured, AddedLines: len(added)}
		// The profile records the candidate revision, so the new path is the
		// correct key even for a rename. A file with no block of its own is not
		// measured: a sibling block proves nothing about this file.
		fileBlocks := blocks[run.Module+"/"+f.Path]
		var notExecuted []int
		if len(fileBlocks) == 0 {
			file.Status = StatusNotMeasured
			file.NotMeasuredLines = len(added)
		} else {
			for _, line := range added {
				switch classify(fileBlocks, line) {
				case executed:
					file.ExecutedLines++
				case notRun:
					file.NotExecutedLines++
					notExecuted = append(notExecuted, line)
				default:
					file.NoBlockLines++
				}
			}
		}
		result.coverage.AddedLines += file.AddedLines
		result.coverage.ExecutedLines += file.ExecutedLines
		result.coverage.NotExecutedLines += file.NotExecutedLines
		result.coverage.NoBlockLines += file.NoBlockLines
		result.coverage.NotMeasuredLines += file.NotMeasuredLines
		result.coverage.Files = append(result.coverage.Files, file)
		result.byPath[f.Path] = file
		for _, r := range runs(notExecuted) {
			if len(result.signals) >= maxSignals {
				break
			}
			if r.overflow > 0 {
				result.signals = append(result.signals, model.Signal{
					Kind: Kind, Path: f.Path, Line: r.start, EndLine: r.end, Side: "new", Severity: severity,
					Summary:  overflowSummary,
					Evidence: stopped(fmt.Sprintf(evidenceOverflow, run.CheckID, r.overflow, r.start, r.end, maxRunsPerFile, command), run.Status),
				})
				continue
			}
			result.signals = append(result.signals, model.Signal{
				Kind: Kind, Path: f.Path, Line: r.start, EndLine: r.end, Side: "new", Severity: severity,
				Summary:  summary,
				Evidence: stopped(fmt.Sprintf(evidenceRun, run.CheckID, r.start, r.end, command), run.Status),
			})
		}
	}
	sort.Slice(result.coverage.Files, func(i, j int) bool {
		return result.coverage.Files[i].Path < result.coverage.Files[j].Path
	})
	if len(result.coverage.Files) > maxReportedFiles {
		result.coverage.Files = result.coverage.Files[:maxReportedFiles]
	}
	return result
}

// Requalify rewrites the evidence of no_test_change signals for files this run
// actually measured. Kind, severity and summary never change, and a file that
// was not measured keeps its original evidence, including the sentence stating
// that existing test coverage has not been measured.
func Requalify(signals []model.Signal, r Result) []model.Signal {
	if r.coverage.Status != StatusMeasured {
		return signals
	}
	out := append([]model.Signal(nil), signals...)
	for i := range out {
		s := &out[i]
		if s.Kind != "no_test_change" {
			continue
		}
		file, ok := r.byPath[s.Path]
		if !ok || file.Status != StatusMeasured {
			continue
		}
		s.Evidence = fmt.Sprintf(evidenceRequalified, r.coverage.CheckID, file.ExecutedLines+file.NotExecutedLines, file.ExecutedLines)
	}
	return out
}

// ModulePath reads the root module path of a snapshot. Exactly one module
// directive must be present: without an unambiguous module path no profile key
// can be built, and every lookup must then miss rather than guess.
func ModulePath(dir string) (string, error) {
	f, err := os.Open(filepath.Join(dir, "go.mod"))
	if err != nil {
		return "", ErrModulePath
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxGoModBytes+1))
	if err != nil || len(b) > maxGoModBytes {
		return "", ErrModulePath
	}
	matches := modulePattern.FindAllStringSubmatch(string(b), -1)
	if len(matches) != 1 {
		return "", ErrModulePath
	}
	module := matches[0][1]
	if module == "" || strings.HasPrefix(module, "/") || strings.ContainsAny(module, ":\x00\\") {
		return "", ErrModulePath
	}
	return module, nil
}

var modulePattern = regexp.MustCompile(`(?m)^module[ \t]+"?([^\s"]+)"?[ \t]*(//.*)?$`)

func stopped(evidence, status string) string {
	if status == "PASS" {
		return evidence
	}
	return evidence + evidenceStopped
}

func inScope(f model.ChangedFile) bool {
	return f.Status != "D" && !f.Binary && strings.HasSuffix(f.Path, ".go") && !strings.HasSuffix(f.Path, "_test.go")
}

func changedLines(f model.ChangedFile) ([]int, int) {
	var added []int
	removed := 0
	for _, h := range f.Hunks {
		for _, d := range h.Lines {
			switch d.Kind {
			case "add":
				if d.NewLine > 0 {
					added = append(added, d.NewLine)
				}
			case "delete":
				if d.OldLine > 0 {
					removed++
				}
			}
		}
	}
	sort.Ints(added)
	return added, removed
}

type state int

const (
	noBlock state = iota
	executed
	notRun
)

// classify is one-directional on purpose: any containing block that ran makes
// the line executed, which can only reduce the number of claims made.
func classify(blocks []Block, line int) state {
	found := false
	for _, b := range blocks {
		if line < b.StartLine || line > b.EndLine {
			continue
		}
		found = true
		if b.Count > 0 {
			return executed
		}
	}
	if !found {
		return noBlock
	}
	return notRun
}

type lineRun struct {
	start, end, overflow int
}

// runs groups unexecuted lines into contiguous ranges and folds everything past
// the per-file cap into a single counted range.
func runs(lines []int) []lineRun {
	var out []lineRun
	for _, line := range lines {
		if n := len(out); n > 0 && out[n-1].end+1 == line {
			out[n-1].end = line
			continue
		}
		out = append(out, lineRun{start: line, end: line})
	}
	if len(out) <= maxRunsPerFile {
		return out
	}
	rest := out[maxRunsPerFile:]
	overflow := 0
	for _, r := range rest {
		overflow += r.end - r.start + 1
	}
	return append(out[:maxRunsPerFile:maxRunsPerFile], lineRun{start: rest[0].start, end: rest[len(rest)-1].end, overflow: overflow})
}
