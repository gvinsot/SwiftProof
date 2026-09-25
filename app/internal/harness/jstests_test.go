package harness

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/gvinsot/SwiftProof/app/internal/model"
)

const generatedTSSource = `import { expect, test } from "vitest";
import { total } from "./cart";

test("applies the discount once", () => {
  expect(total([10], 0.5)).toBe(5);
});
`

var vitestTemplate = []string{"npx", "--no", "vitest", "run", "{file}", "--reporter=json", "--outputFile={results_out}"}

// jestResults renders the Jest-compatible report a runner writes for one file.
func jestResults(file string, statuses map[string]string) string {
	assertions := []map[string]any{}
	for title, status := range statuses {
		assertions = append(assertions, map[string]any{"ancestorTitles": []string{}, "title": title, "status": status})
	}
	b, _ := json.Marshal(map[string]any{"numTotalTests": len(assertions), "testResults": []map[string]any{{"name": "/workspace/" + file, "status": "passed", "assertionResults": assertions}}})
	return string(b)
}

func tsFixture(t *testing.T) *Harness {
	t.Helper()
	h := fixture(t)
	h.opts.Commands["generated_test"] = vitestTemplate
	return h
}

func TestGeneratedJSTitles(t *testing.T) {
	names, err := generatedJSTests("test('a', () => {});\nit(\"b\", async () => {});\ntest(`c`, () => {});\n  test('nested', () => {});\ntest.skip('skipped', () => {});\n")
	if err != nil || !reflect.DeepEqual(names, []string{"a", "b", "c"}) {
		t.Fatalf("got %q, %v", names, err)
	}
	for _, source := range []string{
		"",
		"describe('x', () => {\n  test('a', () => {});\n});",
		"test('a', () => {});\ntest('a', () => {});",
		"test(`a ${1}`, () => {});",
		`test('it\'s', () => {});`,
		"test('', () => {});",
		"test(name, () => {});",
	} {
		if _, err := generatedJSTests(source); err == nil {
			t.Errorf("accepted %q", source)
		}
	}
}

func TestVerifiableJSTemplate(t *testing.T) {
	for _, command := range [][]string{
		vitestTemplate,
		{"npx", "--no", "jest", "{file}", "--json", "--outputFile={results_out}"},
		{"node_modules/.bin/vitest", "run", "{file}", "--reporter=json", "--outputFile={results_out}"},
	} {
		if !verifiableJSTemplate(command) {
			t.Errorf("refused %q", command)
		}
	}
	for _, command := range [][]string{
		{"npx", "vitest", "run", "{file}"},
		{"npm", "test", "--", "{file}", "--outputFile={results_out}"},
		{"sh", "-c", "vitest {file}", "--outputFile={results_out}"},
		{"npx", "vitest", "{file}", "{file}", "--outputFile={results_out}"},
		{"npx", "vitest", "--dir={file}", "--outputFile={results_out}"},
		{"npx", "vitest", "{file}", "--outputFile={results_out}", "--x={results_out}"},
		{"npx", "vitest", "{package}", "--outputFile={results_out}"},
	} {
		if verifiableJSTemplate(command) {
			t.Errorf("accepted %q", command)
		}
	}
}

func TestJestExecutionRequiresExactGeneratedTest(t *testing.T) {
	const path = "src/cart.test.ts"
	names := []string{"applies the discount once"}
	pass := jestResults(path, map[string]string{names[0]: "passed"})
	if c := ValidateJestExecution(model.Check{Status: "PASS", Results: pass}, path, names); c.Status != "PASS" {
		t.Fatal("valid passing report rejected")
	}
	fail := jestResults(path, map[string]string{names[0]: "failed"})
	if c := ValidateJestExecution(model.Check{Status: "FAIL", ExitCode: 1, Results: fail}, path, names); c.Status != "FAIL" {
		t.Fatal("valid failing report rejected")
	}
	nested := `{"testResults":[{"name":"/workspace/src/cart.test.ts","assertionResults":[{"ancestorTitles":["suite"],"title":"applies the discount once","status":"passed"}]}]}`
	twice := `{"testResults":[{"name":"/workspace/src/cart.test.ts","assertionResults":[]},{"name":"/workspace/src/cart.test.ts","assertionResults":[]}]}`
	for _, tc := range []struct {
		name  string
		check model.Check
	}{
		{"no_results", model.Check{Status: "PASS"}},
		{"malformed", model.Check{Status: "PASS", Results: "{"}},
		{"other_file", model.Check{Status: "PASS", Results: jestResults("src/other.test.ts", map[string]string{names[0]: "passed"})}},
		{"skipped", model.Check{Status: "PASS", Results: jestResults(path, map[string]string{names[0]: "skipped"})}},
		{"missing", model.Check{Status: "PASS", Results: jestResults(path, map[string]string{})}},
		{"nested", model.Check{Status: "PASS", Results: nested}},
		{"duplicate_file", model.Check{Status: "PASS", Results: twice}},
		{"unrelated_failure", model.Check{Status: "FAIL", ExitCode: 1, Results: jestResults(path, map[string]string{names[0]: "passed", "other": "failed"})}},
		{"exit_without_failure", model.Check{Status: "FAIL", ExitCode: 1, Results: pass}},
		{"truncated", model.Check{Status: "PASS", Results: pass, Truncated: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if c := ValidateJestExecution(tc.check, path, names); c.Status != "ERROR" {
				t.Fatalf("false execution proof: %+v", c)
			}
		})
	}
}

// runTS drives a generated TypeScript experiment whose runner reports the given
// status on base then candidate.
func runTS(t *testing.T, h *Harness, emit func(run int, payload, log io.Writer) int) map[string]any {
	t.Helper()
	run := 0
	h.executeCapture = func(_ context.Context, _ string, args []string, log, payload io.Writer) execution {
		run++
		for _, arg := range args {
			if strings.Contains(arg, "{results_out}") || strings.Contains(arg, "{file}") {
				t.Errorf("unexpanded placeholder %q", arg)
			}
		}
		if !contains(args, "--outputFile="+ResultsPath) || !contains(args, "src/cart.test.ts") {
			t.Errorf("unexpected argv %q", args)
		}
		return execution{ExitCode: emit(run, payload, log)}
	}
	h.execute = func(context.Context, string, []string, io.Writer) execution {
		t.Fatal("verifiable experiment ran without the results channel")
		return execution{}
	}
	call(t, h, "create_test", map[string]any{"path": "src/cart.test.ts", "content": generatedTSSource, "description": "discount"})
	var result map[string]any
	if err := json.Unmarshal(call(t, h, "run_generated_test", map[string]any{"test_id": "generated-test-1"}), &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestTypeScriptDifferentialReproduces(t *testing.T) {
	h := tsFixture(t)
	result := runTS(t, h, func(run int, payload, _ io.Writer) int {
		status, code := "passed", 0
		if run == 2 {
			status, code = "failed", 1
		}
		fmt.Fprint(payload, coverageFrame(jestResults("src/cart.test.ts", map[string]string{"applies the discount once": status})))
		return code
	})
	e := result["evidence"].(map[string]any)
	if e["status"] != "REPRODUCED" || e["runner"] != RunnerJest {
		t.Fatalf("evidence %+v", e)
	}
	checks := h.Checks()
	if len(checks) != 2 || checks[0].Results == "" || checks[1].Status != "FAIL" {
		t.Fatalf("checks %+v", checks)
	}
	kinds := map[string]bool{}
	for _, a := range h.Artifacts() {
		kinds[a.Kind] = true
	}
	if !kinds["test_results"] || !kinds["generated_test"] {
		t.Fatalf("results and reproducer must be retained: %+v", h.Artifacts())
	}
}

func TestTypeScriptDifferentialInconclusiveCases(t *testing.T) {
	for _, tc := range []struct {
		name string
		emit func(run int, payload, log io.Writer) int
	}{
		{"no_report", func(run int, _, log io.Writer) int {
			// A log line cannot stand in for the report channel.
			fmt.Fprint(log, jestResults("src/cart.test.ts", map[string]string{"applies the discount once": "failed"}))
			return run - 1
		}},
		{"unrelated_failure", func(run int, payload, _ io.Writer) int {
			statuses := map[string]string{"applies the discount once": "passed"}
			if run == 2 {
				statuses["something else"] = "failed"
			}
			fmt.Fprint(payload, coverageFrame(jestResults("src/cart.test.ts", statuses)))
			return run - 1
		}},
		{"baseline_fails", func(_ int, payload, _ io.Writer) int {
			fmt.Fprint(payload, coverageFrame(jestResults("src/cart.test.ts", map[string]string{"applies the discount once": "failed"})))
			return 1
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := runTS(t, tsFixture(t), tc.emit)["evidence"].(map[string]any)
			if e["status"] != "UNVERIFIED" {
				t.Fatalf("evidence %+v", e)
			}
		})
	}
}

func TestTypeScriptWithoutVerifiableTemplateStaysUnverified(t *testing.T) {
	h := fixture(t)
	h.opts.Commands["generated_test"] = []string{"npx", "vitest", "run", "{file}"}
	h.execute = func(_ context.Context, _ string, _ []string, w io.Writer) execution { return execution{ExitCode: 0} }
	// Free-form content is still accepted when nothing could verify titles.
	call(t, h, "create_test", map[string]any{"path": "src/cart.test.ts", "content": "describe('x', () => {})"})
	var result map[string]any
	_ = json.Unmarshal(call(t, h, "run_generated_test", map[string]any{"test_id": "generated-test-1"}), &result)
	if e := result["evidence"].(map[string]any); e["status"] != "UNVERIFIED" || e["runner"] != nil {
		t.Fatalf("evidence %+v", e)
	}
	h2 := tsFixture(t)
	if _, err := h2.createTest("src/cart.test.ts", "describe('x', () => {})", ""); err == nil {
		t.Fatal("verifiable template accepted a test without top-level titles")
	}
}

func TestNormalizedResultsAreRedactedAndBounded(t *testing.T) {
	raw := `{"testResults":[{"name":"/workspace/a.test.ts","extra":1,"assertionResults":[{"ancestorTitles":[],"title":"t","status":"failed","failureMessages":["token Bearer abcdefghijklmnop ` + strings.Repeat("x", 10000) + `"]}]}]}`
	got, err := normalizeJestReport([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got, "abcdefghijklmnop") || strings.Contains(got, "extra") || len(got) > 5000 {
		t.Fatalf("normalized report %q", got)
	}
	if c := ValidateJestExecution(model.Check{Status: "FAIL", ExitCode: 1, Results: got}, "a.test.ts", []string{"t"}); c.Status != "FAIL" {
		t.Fatal("normalized report no longer validates")
	}
	for _, bad := range []string{"", "[]", `{"other":1}`, "\xff"} {
		if _, err := normalizeJestReport([]byte(bad)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}
