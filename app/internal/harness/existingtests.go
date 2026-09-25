package harness

// Per-name outcomes of existing Go tests (F0c wrote this file; F3 owns it
// afterwards). The exported signatures and the status rules are frozen: F2,
// F3, F4 and F6b rely on them. Only reason texts may be refined.

import (
	"bufio"
	"bytes"
	"encoding/json"
	"strings"

	"github.com/gvinsot/SwiftProof/app/internal/model"
)

// goTestLineLimit bounds one go test -json line. A longer line makes the whole
// log unreadable rather than silently skipped.
const goTestLineLimit = 1 << 20

// GoTestOutcome returns the single terminal action ("pass", "fail", "skip") that
// go test -json recorded for the top-level test name, and its package. It returns
// ("","") unless the name has exactly one "run" event and exactly one terminal
// event, and all its events share one non-empty Package. Non-JSON lines are
// ignored; a scanner error (1 MiB line buffer) returns ("","").
//
// The terminal event must also follow the run event. A test can print text that
// test2json turns into events, so a second terminal event (for example a forged
// pass after a real fail) makes the outcome unknown rather than either one.
// Subtest events ("Name/sub") are not events of name.
func GoTestOutcome(output, name string) (action, pkg string) {
	if name == "" {
		return "", ""
	}
	runs, terminals := 0, 0
	runSeen := false
	terminal, pkg := "", ""
	orderOK := true
	scanner := bufio.NewScanner(strings.NewReader(output))
	scanner.Buffer(make([]byte, 0, 64*1024), goTestLineLimit)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var event struct {
			Action  string `json:"Action"`
			Test    string `json:"Test"`
			Package string `json:"Package"`
		}
		if json.Unmarshal(line, &event) != nil || event.Test != name {
			continue
		}
		if event.Package == "" || pkg != "" && event.Package != pkg {
			return "", ""
		}
		pkg = event.Package
		switch event.Action {
		case "run":
			runs++
			runSeen = true
		case "pass", "fail", "skip":
			terminals++
			terminal = event.Action
			if !runSeen {
				orderOK = false
			}
		}
	}
	if scanner.Err() != nil || runs != 1 || terminals != 1 || !orderOK || pkg == "" {
		return "", ""
	}
	return terminal, pkg
}

// Fixed reason texts of ClassifyExistingTest. They describe the recorded
// runs only.
const (
	reasonFailsOnCandidate    = "the test passed on the baseline and failed on the candidate-side tree"
	reasonPassesOnCandidate   = "the test passed on the baseline and on the candidate-side tree"
	reasonCommandMismatch     = "the baseline and candidate-side runs did not use one identical recorded command"
	reasonBaselineNotPassed   = "the baseline run did not pass cleanly (status PASS, exit code 0, complete log)"
	reasonBaselineOutcome     = "the baseline log does not record exactly one run and one pass of this test in one package"
	reasonCandidateTimeout    = "the candidate-side run timed out"
	reasonCandidateIncomplete = "the candidate-side run did not complete"
	reasonCandidateTrunc      = "the candidate-side log was truncated"
	reasonCandidateExit       = "the candidate-side run ended with an exit code outside the test-failure range"
	reasonCandidateBuild      = "the candidate-side package did not build or set up, so the test did not run"
	reasonCandidateOutcome    = "the candidate-side log does not record exactly one run and one terminal result of this test in the baseline's package"
)

// ClassifyExistingTest compares one named Go test run on a baseline tree and a
// candidate-side tree. It returns StatusFailsOnCandidate, StatusPassesOnCandidate
// or StatusUnverified, with a fixed reason. Rules (all must hold, else UNVERIFIED):
//   - base.Command and candidate.Command are equal and non-empty;
//   - baseline: Status PASS, ExitCode 0, !Truncated, GoTestOutcome == ("pass", p), p != "";
//   - FAILS:  candidate Status FAIL, ExitCode 1..124, !Truncated, GoTestOutcome == ("fail", p);
//   - PASSES: candidate Status PASS, ExitCode 0, !Truncated, GoTestOutcome == ("pass", p).
//
// A pass event inside a FAIL, TIMEOUT, ERROR or truncated candidate check never yields
// PASSES. For a multi-name check this gives FAILS for names whose outcome is fail
// and UNVERIFIED for the rest. Build-failure detection only picks the reason text.
//
// It does not look at Replayed(): the live-baseline rule (§1.11) belongs to
// callers and verifiers.
func ClassifyExistingTest(base, candidate model.Check, name string) (status, reason string) {
	if len(base.Command) == 0 || !equalStrings(base.Command, candidate.Command) {
		return model.StatusUnverified, reasonCommandMismatch
	}
	if base.Status != "PASS" || base.ExitCode != 0 || base.Truncated {
		return model.StatusUnverified, reasonBaselineNotPassed
	}
	baseAction, pkg := GoTestOutcome(base.Output, name)
	if baseAction != "pass" || pkg == "" {
		return model.StatusUnverified, reasonBaselineOutcome
	}
	switch candidate.Status {
	case "PASS", "FAIL":
	case "TIMEOUT":
		return model.StatusUnverified, reasonCandidateTimeout
	default:
		return model.StatusUnverified, reasonCandidateIncomplete
	}
	if candidate.Truncated {
		return model.StatusUnverified, reasonCandidateTrunc
	}
	action, candidatePkg := GoTestOutcome(candidate.Output, name)
	outcomeOK := candidatePkg == pkg
	switch candidate.Status {
	case "FAIL":
		if candidate.ExitCode < 1 || candidate.ExitCode > 124 {
			return model.StatusUnverified, reasonCandidateExit
		}
		if outcomeOK && action == "fail" {
			return model.StatusFailsOnCandidate, reasonFailsOnCandidate
		}
		if goBuildFailure(candidate.Output) {
			return model.StatusUnverified, reasonCandidateBuild
		}
		return model.StatusUnverified, reasonCandidateOutcome
	default: // PASS
		if candidate.ExitCode != 0 {
			return model.StatusUnverified, reasonCandidateExit
		}
		if outcomeOK && action == "pass" {
			return model.StatusPassesOnCandidate, reasonPassesOnCandidate
		}
		return model.StatusUnverified, reasonCandidateOutcome
	}
}

// goBuildFailure recognizes the markers go test prints when a package does not
// build or set up. It only selects a reason text.
func goBuildFailure(output string) bool {
	for _, marker := range []string{"[build failed]", "[setup failed]", "build failed", "setup failed"} {
		if strings.Contains(output, marker) {
			return true
		}
	}
	return false
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
