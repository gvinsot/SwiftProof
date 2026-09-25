package harness

import (
	"fmt"
	"strings"
	"testing"

	"github.com/gvinsot/SwiftProof/app/internal/model"
)

// ev renders one go test -json event.
func ev(action, test, pkg string) string {
	return fmt.Sprintf(`{"Time":"2026-09-25T10:00:00Z","Action":%q,"Package":%q,"Test":%q}`, action, pkg, test)
}

func events(lines ...string) string { return strings.Join(lines, "\n") + "\n" }

const pkgA = "example.test/shop/cart"

func TestGoTestOutcome(t *testing.T) {
	long := `{"Action":"output","Test":"TestA","Package":"` + pkgA + `","Output":"` + strings.Repeat("x", 1<<20) + `"}`
	cases := []struct {
		name, output, test string
		action, pkg        string
	}{
		{"pass", events(ev("start", "", pkgA), ev("run", "TestA", pkgA), ev("output", "TestA", pkgA), ev("pass", "TestA", pkgA), ev("pass", "", pkgA)), "TestA", "pass", pkgA},
		{"fail", events(ev("run", "TestA", pkgA), ev("fail", "TestA", pkgA)), "TestA", "fail", pkgA},
		{"skip", events(ev("run", "TestA", pkgA), ev("skip", "TestA", pkgA)), "TestA", "skip", pkgA},
		{"subtests_are_not_the_test", events(ev("run", "TestA", pkgA), ev("run", "TestA/sub", pkgA), ev("fail", "TestA/sub", pkgA), ev("pass", "TestA", pkgA)), "TestA", "pass", pkgA},
		{"other_tests_ignored", events(ev("run", "TestB", "other/pkg"), ev("run", "TestA", pkgA), ev("fail", "TestB", "other/pkg"), ev("pass", "TestA", pkgA)), "TestA", "pass", pkgA},
		{"non_json_lines_ignored", "=== RUN   TestA\n" + events(ev("run", "TestA", pkgA)) + "--- PASS: TestA (0.00s)\nPASS\nnull\n\"text\"\n[1]\n" + events(ev("pass", "TestA", pkgA)) + "ok  \t" + pkgA + "\t0.01s\n", "TestA", "pass", pkgA},
		{"leading_whitespace_json", "  " + ev("run", "TestA", pkgA) + "\n\t" + ev("pass", "TestA", pkgA) + "\n", "TestA", "pass", pkgA},
		{"forged_pass_after_real_fail", events(ev("run", "TestA", pkgA), ev("fail", "TestA", pkgA), ev("pass", "TestA", pkgA)), "TestA", "", ""},
		{"two_run_events", events(ev("run", "TestA", pkgA), ev("run", "TestA", pkgA), ev("pass", "TestA", pkgA)), "TestA", "", ""},
		{"no_run_event", events(ev("pass", "TestA", pkgA)), "TestA", "", ""},
		{"no_terminal_event", events(ev("run", "TestA", pkgA), ev("output", "TestA", pkgA)), "TestA", "", ""},
		{"terminal_before_run", events(ev("pass", "TestA", pkgA), ev("run", "TestA", pkgA)), "TestA", "", ""},
		{"package_mismatch", events(ev("run", "TestA", pkgA), ev("pass", "TestA", "other/pkg")), "TestA", "", ""},
		{"output_event_in_other_package", events(ev("run", "TestA", pkgA), ev("output", "TestA", "other/pkg"), ev("pass", "TestA", pkgA)), "TestA", "", ""},
		{"empty_package", events(ev("run", "TestA", ""), ev("pass", "TestA", "")), "TestA", "", ""},
		{"absent_test", events(ev("run", "TestB", pkgA), ev("pass", "TestB", pkgA)), "TestA", "", ""},
		{"empty_name", events(ev("run", "", pkgA), ev("pass", "", pkgA)), "", "", ""},
		{"line_over_1MiB", events(ev("run", "TestA", pkgA), long, ev("pass", "TestA", pkgA)), "TestA", "", ""},
		{"empty", "", "TestA", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			action, pkg := GoTestOutcome(tc.output, tc.test)
			if action != tc.action || pkg != tc.pkg {
				t.Fatalf("got (%q, %q), want (%q, %q)", action, pkg, tc.action, tc.pkg)
			}
		})
	}
}

func goCheck(status string, exit int, output string) model.Check {
	return model.Check{ID: "check-1", Kind: model.CheckBaseTestBase, Status: status, ExitCode: exit, Output: output, Command: []string{"go", "test", "-json", "-count=1", "-run", "^(TestA|TestB)$", "./cart"}}
}

func TestClassifyExistingTest(t *testing.T) {
	basePass := goCheck("PASS", 0, events(ev("run", "TestA", pkgA), ev("pass", "TestA", pkgA), ev("run", "TestB", pkgA), ev("pass", "TestB", pkgA)))
	candFail := goCheck("FAIL", 1, events(ev("run", "TestA", pkgA), ev("fail", "TestA", pkgA), ev("run", "TestB", pkgA), ev("pass", "TestB", pkgA)))
	candPass := goCheck("PASS", 0, events(ev("run", "TestA", pkgA), ev("pass", "TestA", pkgA)))
	with := func(c model.Check, f func(*model.Check)) model.Check { f(&c); return c }
	cases := []struct {
		name            string
		base, candidate model.Check
		test            string
		status          string
		reason          string
	}{
		{"fails_on_candidate", basePass, candFail, "TestA", model.StatusFailsOnCandidate, reasonFailsOnCandidate},
		{"passes_on_candidate", basePass, candPass, "TestA", model.StatusPassesOnCandidate, reasonPassesOnCandidate},
		{"replayed_base_is_the_callers_concern", with(basePass, func(c *model.Check) { c.Cache = &model.CheckCache{Status: model.CacheHit, LiveRuns: 1} }), candFail, "TestA", model.StatusFailsOnCandidate, reasonFailsOnCandidate},
		// A pass event inside a FAIL check never yields PASSES; its sibling that
		// failed is FAILS.
		{"pass_inside_fail_check", basePass, candFail, "TestB", model.StatusUnverified, reasonCandidateOutcome},
		{"forged_pass_after_real_fail", basePass, goCheck("PASS", 0, events(ev("run", "TestA", pkgA), ev("fail", "TestA", pkgA), ev("pass", "TestA", pkgA))), "TestA", model.StatusUnverified, reasonCandidateOutcome},
		{"forged_fail_after_real_pass", basePass, goCheck("FAIL", 1, events(ev("run", "TestA", pkgA), ev("pass", "TestA", pkgA), ev("fail", "TestA", pkgA))), "TestA", model.StatusUnverified, reasonCandidateOutcome},
		{"truncated_pass", basePass, with(candPass, func(c *model.Check) { c.Truncated = true }), "TestA", model.StatusUnverified, reasonCandidateTrunc},
		{"truncated_fail", basePass, with(candFail, func(c *model.Check) { c.Truncated = true }), "TestA", model.StatusUnverified, reasonCandidateTrunc},
		{"two_run_events", basePass, goCheck("FAIL", 1, events(ev("run", "TestA", pkgA), ev("run", "TestA", pkgA), ev("fail", "TestA", pkgA))), "TestA", model.StatusUnverified, reasonCandidateOutcome},
		{"package_mismatch", basePass, goCheck("FAIL", 1, events(ev("run", "TestA", "other/cart"), ev("fail", "TestA", "other/cart"))), "TestA", model.StatusUnverified, reasonCandidateOutcome},
		{"timeout_with_pass_event", basePass, with(candPass, func(c *model.Check) { c.Status, c.ExitCode = "TIMEOUT", -1 }), "TestA", model.StatusUnverified, reasonCandidateTimeout},
		{"error_with_pass_event", basePass, with(candPass, func(c *model.Check) { c.Status = "ERROR" }), "TestA", model.StatusUnverified, reasonCandidateIncomplete},
		{"error_with_fail_event", basePass, with(candFail, func(c *model.Check) { c.Status, c.ExitCode = "ERROR", 125 }), "TestA", model.StatusUnverified, reasonCandidateIncomplete},
		{"skipped", basePass, goCheck("SKIPPED", -1, ""), "TestA", model.StatusUnverified, reasonCandidateIncomplete},
		{"fail_exit_out_of_range", basePass, with(candFail, func(c *model.Check) { c.ExitCode = 125 }), "TestA", model.StatusUnverified, reasonCandidateExit},
		{"fail_exit_zero", basePass, with(candFail, func(c *model.Check) { c.ExitCode = 0 }), "TestA", model.StatusUnverified, reasonCandidateExit},
		{"pass_nonzero_exit", basePass, with(candPass, func(c *model.Check) { c.ExitCode = 1 }), "TestA", model.StatusUnverified, reasonCandidateExit},
		{"build_failure", basePass, goCheck("FAIL", 1, "# "+pkgA+"\ncart.go:3:1: undefined: Total\nFAIL\t"+pkgA+" [build failed]\n"), "TestA", model.StatusUnverified, reasonCandidateBuild},
		{"skip_on_candidate", basePass, goCheck("PASS", 0, events(ev("run", "TestA", pkgA), ev("skip", "TestA", pkgA))), "TestA", model.StatusUnverified, reasonCandidateOutcome},
		{"different_commands", basePass, with(candFail, func(c *model.Check) { c.Command = append([]string(nil), c.Command...); c.Command[3] = "-count=2" }), "TestA", model.StatusUnverified, reasonCommandMismatch},
		{"empty_commands", with(basePass, func(c *model.Check) { c.Command = nil }), with(candFail, func(c *model.Check) { c.Command = nil }), "TestA", model.StatusUnverified, reasonCommandMismatch},
		{"base_failed", candFail, candFail, "TestA", model.StatusUnverified, reasonBaselineNotPassed},
		{"base_truncated", with(basePass, func(c *model.Check) { c.Truncated = true }), candFail, "TestA", model.StatusUnverified, reasonBaselineNotPassed},
		{"base_nonzero_exit", with(basePass, func(c *model.Check) { c.ExitCode = 2 }), candFail, "TestA", model.StatusUnverified, reasonBaselineNotPassed},
		{"base_skipped_test", goCheck("PASS", 0, events(ev("run", "TestA", pkgA), ev("skip", "TestA", pkgA))), candFail, "TestA", model.StatusUnverified, reasonBaselineOutcome},
		{"base_forged_pass", goCheck("PASS", 0, events(ev("run", "TestA", pkgA), ev("fail", "TestA", pkgA), ev("pass", "TestA", pkgA))), candFail, "TestA", model.StatusUnverified, reasonBaselineOutcome},
		{"absent_name", basePass, candFail, "TestC", model.StatusUnverified, reasonBaselineOutcome},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status, reason := ClassifyExistingTest(tc.base, tc.candidate, tc.test)
			if status != tc.status || reason != tc.reason {
				t.Fatalf("got (%s, %q), want (%s, %q)", status, reason, tc.status, tc.reason)
			}
		})
	}
	for _, reason := range []string{reasonFailsOnCandidate, reasonPassesOnCandidate, reasonCommandMismatch, reasonBaselineNotPassed, reasonBaselineOutcome, reasonCandidateTimeout, reasonCandidateIncomplete, reasonCandidateTrunc, reasonCandidateExit, reasonCandidateBuild, reasonCandidateOutcome} {
		for _, word := range []string{"regression", "bug", "verified", "tested", "correct", "safe", "masked"} {
			if strings.Contains(strings.ToLower(reason), word) {
				t.Errorf("reason %q uses the forbidden word %q", reason, word)
			}
		}
	}
}
