package harness

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/gvinsot/SwiftProof/app/internal/config"
	"github.com/gvinsot/SwiftProof/app/internal/coverage"
	"github.com/gvinsot/SwiftProof/app/internal/model"
	"github.com/gvinsot/SwiftProof/app/internal/redact"
)

// Runner names recorded on differential evidence. Each names the verifier that
// establishes the generated named tests actually ran.
const (
	RunnerGo   = "go_test_json"
	RunnerJest = "jest_json"
)

// ResultsPath is the fixed in-container path a verifiable JavaScript/TypeScript
// template writes its JSON report to. /tmp is a fresh tmpfs per run, so a
// committed or stale report cannot occupy it.
const ResultsPath = "/tmp/swiftproof-test-results.json"

// jsTopLevelTest matches a test declared at column 0 with a static title.
// Escapes and template interpolation are refused so the extracted title is
// byte-for-byte the title the runner reports.
var jsTopLevelTest = regexp.MustCompile("(?m)^(?:test|it)\\(\\s*(?:'([^'\\\\\\n]*)'|\"([^\"\\\\\\n]*)\"|`([^`\\\\$\\n]*)`)\\s*,")

func isJSTestPath(path string) bool {
	b := strings.ToLower(filepath.Base(path))
	for _, suffix := range []string{".test.ts", ".test.tsx", ".spec.ts", ".spec.tsx", ".test.js", ".spec.js"} {
		if strings.HasSuffix(b, suffix) {
			return true
		}
	}
	return false
}

// generatedJSTests extracts the titles of top-level test()/it() calls. The
// extraction is lexical; it is sound because validation requires every
// extracted title to appear, with no ancestor describe block, in the runner's
// report for this exact file. A title the extraction misreads can only make
// the outcome inconclusive, never reproduced.
func generatedJSTests(source string) ([]string, error) {
	names := []string{}
	seen := map[string]bool{}
	for _, m := range jsTopLevelTest.FindAllStringSubmatch(source, -1) {
		name := m[1] + m[2] + m[3]
		if strings.TrimSpace(name) == "" {
			return nil, errors.New("generated test titles must not be empty")
		}
		if seen[name] {
			return nil, fmt.Errorf("duplicate generated test title %q", name)
		}
		seen[name] = true
		names = append(names, name)
	}
	if len(names) == 0 {
		return nil, errors.New("generated JavaScript/TypeScript file must declare at least one top-level test(\"title\", ...) or it(\"title\", ...) call at column 0 with a static title and no describe block")
	}
	return names, nil
}

// verifiableJSTemplate requires the generated file as one standalone target and
// the runner's JSON report written to {results_out}. Package-manager scripts and
// shells are refused: they run repository-defined commands that decide what
// executes and what gets written to the report.
func verifiableJSTemplate(command []string) bool {
	if len(command) < 2 {
		return false
	}
	switch filepath.Base(command[0]) {
	case "npm", "yarn", "pnpm", "bun", "sh", "bash", "env":
		return false
	}
	targets, results := 0, 0
	for _, arg := range command[1:] {
		if arg == "{file}" {
			targets++
		} else if strings.Contains(arg, "{file}") || strings.Contains(arg, "{package}") {
			return false
		}
		results += strings.Count(arg, config.ResultsPlaceholder)
	}
	return targets == 1 && results == 1
}

// jestReport is the subset of the Jest JSON report (also written by Vitest's
// json reporter) that verification reads. The harness stores it re-encoded in
// this shape, so the saved report and the raw runner output parse alike.
type jestReport struct {
	TestResults []jestFile `json:"testResults"`
}

type jestFile struct {
	Name             string          `json:"name"`
	Status           string          `json:"status,omitempty"`
	Message          string          `json:"message,omitempty"`
	AssertionResults []jestAssertion `json:"assertionResults"`
}

type jestAssertion struct {
	AncestorTitles  []string `json:"ancestorTitles"`
	Title           string   `json:"title"`
	Status          string   `json:"status"`
	FailureMessages []string `json:"failureMessages,omitempty"`
}

// normalizeJestReport keeps only what verification and a reviewer need. Every
// string it keeps is redacted (file names, statuses, titles, ancestor titles
// and messages), and messages are bounded. A title that redaction changes no
// longer matches the name extracted from the generated source, so such a test
// can only be inconclusive. The caller rejects a result that is not a Redact
// fixed point after encoding.
func normalizeJestReport(raw []byte) (string, error) {
	if !utf8.Valid(raw) {
		return "", errors.New("test results are not valid UTF-8")
	}
	var report jestReport
	if err := json.Unmarshal(raw, &report); err != nil {
		return "", fmt.Errorf("test results are not a Jest-compatible JSON report: %w", err)
	}
	if report.TestResults == nil {
		return "", errors.New("test results contain no testResults array")
	}
	for i := range report.TestResults {
		file := &report.TestResults[i]
		file.Name = Redact(file.Name)
		file.Status = Redact(file.Status)
		file.Message = truncateUTF8(Redact(file.Message), 4096)
		for j := range file.AssertionResults {
			a := &file.AssertionResults[j]
			a.Title = Redact(a.Title)
			a.Status = Redact(a.Status)
			for k := range a.AncestorTitles {
				a.AncestorTitles[k] = Redact(a.AncestorTitles[k])
			}
			for k := range a.FailureMessages {
				a.FailureMessages[k] = truncateUTF8(Redact(a.FailureMessages[k]), 4096)
			}
		}
	}
	b, err := json.Marshal(report)
	return string(b), err
}

// runWithResults executes a verifiable JavaScript/TypeScript template and
// attaches the runner's normalized JSON report to the recorded check. A report
// that is missing, cut short or unreadable makes the check an ERROR: without it
// nothing establishes that the generated tests ran.
func (h *Harness) runWithResults(ctx context.Context, kind, dir string, command []string) model.Check {
	return h.runWithResultsOptions(ctx, kind, dir, command, runOptions{})
}

// resultsOverBudget is the fixed text of a report that could not be recorded
// on the check because the report-wide results budget was used up.
const resultsOverBudget = "structured results exceeded the report budget; retained as an artifact only"

// runWithResultsOptions is runWithResults with run options; o.capture is
// always ResultsPath. Caller holds h.mu.
//
// Every recorded Check.Results is a Redact fixed point, so report sanitizing
// can never alter it; a report that is not one after normalization is
// rejected as unreadable. Results that would exceed what remains of
// ResultsBudget for the run's side (resultsRemainingFor: candidate-side
// results share at most half of it) are retained as the hashed test_results
// artifact only, and the check becomes ERROR.
func (h *Harness) runWithResultsOptions(ctx context.Context, kind, dir string, command []string, o runOptions) model.Check {
	o.capture = ResultsPath
	c, payload, truncated := h.runWithOptions(ctx, kind, dir, command, o)
	if c.Status != "PASS" && c.Status != "FAIL" {
		return c
	}
	var results string
	raw, err := coverage.DecodeFrame(payload, truncated)
	if err != nil {
		err = errors.New("the test runner did not emit one complete JSON report at " + config.ResultsPlaceholder)
	} else {
		results, err = normalizeJestReport(raw)
	}
	if err == nil && !redact.IsFixedPoint(results) {
		err = errors.New("test results are unreadable: redaction would alter the normalized report")
	}
	if err == nil && len(results) > PayloadLimit(h.opts.MaxOutputBytes) {
		err = errors.New("test results exceed the sandbox payload budget")
	}
	if err == nil {
		err = h.saveArtifact(c.ID+"-results.json", model.ArtifactTestResults, []byte(results))
	}
	if err == nil && len(results) > h.resultsRemainingFor(kind) {
		err = errors.New(resultsOverBudget)
	}
	if err != nil {
		c.Status = "ERROR"
		c.Output = truncateUTF8(c.Output+"\n"+Redact(err.Error()), h.opts.MaxOutputBytes)
	} else {
		c.Results = results
	}
	h.replaceCheck(c)
	return c
}

// ValidateJestExecution requires, in the report for exactly the generated file,
// one top-level result for each generated title. A passing check needs every
// title passed; a failing check needs one of them failed. Skipped, missing,
// nested, duplicated and unrelated results are inconclusive.
func ValidateJestExecution(check model.Check, path string, names []string) model.Check {
	if check.Status != "PASS" && check.Status != "FAIL" {
		return check
	}
	var report jestReport
	if check.Truncated || check.Results == "" || json.Unmarshal([]byte(check.Results), &report) != nil {
		check.Status = "ERROR"
		return check
	}
	want := "/workspace/" + filepath.ToSlash(filepath.Clean(filepath.FromSlash(path)))
	var file *jestFile
	for i := range report.TestResults {
		if report.TestResults[i].Name == want {
			if file != nil {
				check.Status = "ERROR"
				return check
			}
			file = &report.TestResults[i]
		}
	}
	if file == nil {
		check.Status = "ERROR"
		return check
	}
	status := map[string]string{}
	count := map[string]int{}
	for _, a := range file.AssertionResults {
		if len(a.AncestorTitles) == 0 {
			status[a.Title] = a.Status
			count[a.Title]++
		}
	}
	allPass := len(names) > 0
	failed := false
	for _, name := range names {
		if count[name] != 1 {
			allPass = false
			continue
		}
		allPass = allPass && status[name] == "passed"
		failed = failed || status[name] == "failed"
	}
	if check.Status == "PASS" && !allPass || check.Status == "FAIL" && !failed {
		check.Status = "ERROR"
	}
	return check
}

// ValidateExecution dispatches to the verifier recorded on the evidence. An
// unknown runner is never verified.
func ValidateExecution(runner string, check model.Check, path string, names []string) (model.Check, bool) {
	switch runner {
	case RunnerGo:
		return ValidateGoExecution(check, names), true
	case RunnerJest:
		return ValidateJestExecution(check, path, names), true
	}
	return check, false
}
