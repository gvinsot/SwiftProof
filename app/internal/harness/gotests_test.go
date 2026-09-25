package harness

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gvinsot/SwiftProof/app/internal/model"
)

func TestGeneratedGoDeclarationsAndCollisions(t *testing.T) {
	h := fixture(t)
	for _, test := range []struct{ path, source string }{
		{"pkg/empty_test.go", "package pkg"},
		{"pkg/_ignored_test.go", generatedSource},
		{"pkg/.ignored_test.go", generatedSource},
		{"pkg/invalid_test.go", `package pkg;func TestBroken(){}`},
		{"pkg/invalid_test.go", `package pkg;import "testing";func TestnotSelected(t *testing.T){}`},
		{"pkg/invalid_test.go", `package pkg;import "testing";func TestWrong(t *testing.B){}`},
	} {
		if _, err := h.createTest(test.path, test.source, ""); err == nil {
			t.Errorf("accepted non-runnable test %s %s", test.path, test.source)
		}
	}
	if err := os.WriteFile(filepath.Join(h.base, "pkg", "existing_test.go"), []byte(generatedSource), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := h.createTest("pkg/new_test.go", generatedSource, ""); err == nil {
		t.Fatal("accepted colliding existing test name")
	}
	aliased := strings.ReplaceAll(strings.Replace(generatedSource, `"testing"`, `check "testing"`, 1), "testing.T", "check.T")
	if _, err := generatedGoTests("alias_test.go", aliased); err != nil {
		t.Fatalf("valid testing import alias refused: %v", err)
	}
}

func TestGoExecutionRequiresExactGeneratedTest(t *testing.T) {
	var output strings.Builder
	writeGoEvents(&output, "pass")
	valid := model.Check{Status: "PASS", ExitCode: 0, Output: output.String()}
	if c := ValidateGoExecution(valid, []string{"TestSwiftProof"}); c.Status != "PASS" {
		t.Fatal("valid Go execution rejected")
	}
	for _, tc := range []struct {
		name  string
		check model.Check
	}{
		{"empty", model.Check{Status: "PASS", ExitCode: 0}},
		{"unrelated", model.Check{Status: "FAIL", ExitCode: 1, Output: `{"Action":"fail","Test":"TestUnrelated"}`}},
		{"package_only", model.Check{Status: "FAIL", ExitCode: 1, Output: `{"Action":"fail","Package":"pkg"}`}},
		{"no_run", model.Check{Status: "PASS", ExitCode: 0, Output: `{"Action":"pass","Test":"TestSwiftProof"}`}},
		{"skip", model.Check{Status: "PASS", ExitCode: 0, Output: "{\"Action\":\"run\",\"Test\":\"TestSwiftProof\"}\n{\"Action\":\"skip\",\"Test\":\"TestSwiftProof\"}"}},
		{"truncated", model.Check{Status: "PASS", ExitCode: 0, Output: output.String(), Truncated: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if c := ValidateGoExecution(tc.check, []string{"TestSwiftProof"}); c.Status != "ERROR" {
				t.Fatalf("false execution proof: %+v", c)
			}
		})
	}
}

func TestUnrelatedFailureIsNotAReproducedGeneratedTest(t *testing.T) {
	h := fixture(t)
	count := 0
	h.execute = func(_ context.Context, _ string, _ []string, w io.Writer) execution {
		count++
		writeGoEvents(w, "pass")
		if count == 2 {
			fmt.Fprintln(w, `{"Action":"fail","Test":"TestUnrelated"}`)
			return execution{ExitCode: 1}
		}
		return execution{ExitCode: 0}
	}
	call(t, h, "create_test", map[string]any{"path": "pkg/new_test.go", "content": generatedSource})
	call(t, h, "run_generated_test", map[string]any{"test_id": "generated-test-1"})
	if h.Evidence()[0].Status != "UNVERIFIED" {
		t.Fatal("unrelated failure attributed to generated test")
	}
}

func TestUnsupportedRunnerRemainsUnverified(t *testing.T) {
	h := fixture(t)
	h.opts.Commands["generated_test"] = []string{"python", "{file}"}
	count := 0
	h.execute = func(context.Context, string, []string, io.Writer) execution {
		count++
		if count == 2 {
			return execution{ExitCode: 1}
		}
		return execution{ExitCode: 0}
	}
	call(t, h, "create_test", map[string]any{"path": "test_case.py", "content": "assert True"})
	call(t, h, "run_generated_test", map[string]any{"test_id": "generated-test-1"})
	if h.Evidence()[0].Status != "UNVERIFIED" {
		t.Fatal("unknown runner claimed verified differential outcome")
	}
}

func TestGeneratedDirectoriesAreRemoved(t *testing.T) {
	h := fixture(t)
	h.execute = func(_ context.Context, _ string, _ []string, w io.Writer) execution {
		writeGoEvents(w, "pass")
		return execution{ExitCode: 0}
	}
	call(t, h, "create_test", map[string]any{"path": "new/nested/case_test.go", "content": generatedSource})
	call(t, h, "run_generated_test", map[string]any{"test_id": "generated-test-1"})
	for _, root := range []string{h.base, h.candidate} {
		if _, err := os.Stat(filepath.Join(root, "new")); !os.IsNotExist(err) {
			t.Fatal("generated directory mutated later snapshot state")
		}
	}
}

func TestRunExistingTest(t *testing.T) {
	h := fixture(t)
	if err := os.WriteFile(filepath.Join(h.candidate, "pkg", "existing_test.go"), []byte(generatedSource), 0644); err != nil {
		t.Fatal(err)
	}
	h.execute = func(_ context.Context, _ string, args []string, w io.Writer) execution {
		if args[len(args)-1] != "^(TestSwiftProof)$" {
			t.Fatal("existing Go test was not selected")
		}
		writeGoEvents(w, "pass")
		return execution{ExitCode: 0}
	}
	call(t, h, "run_test", map[string]any{"path": "pkg/existing_test.go"})
	if h.Checks()[0].Kind != "existing_test" || len(h.Evidence()) != 0 {
		t.Fatal("existing test incorrectly emitted differential evidence")
	}
}

func TestGoProofRejectsMultiPackageAndExecutionOverrides(t *testing.T) {
	for _, command := range [][]string{
		{"go", "test", "./...", "{package}"},
		{"go", "test", "-C=other", "{package}"},
		{"go", "test", "-overlay=overlay.json", "{package}"},
		{"go", "test", "-exec=wrapper", "{package}"},
		{"go", "test", "{package}", "-args"},
	} {
		if verifiableGoTemplate(command) {
			t.Fatalf("unsafe proof template accepted: %v", command)
		}
	}
	if !verifiableGoTemplate([]string{"go", "test", "-race", "-tags=integration", "{package}"}) {
		t.Fatal("safe single-package template rejected")
	}
	check := model.Check{Status: "FAIL", ExitCode: 1, Output: "{\"Action\":\"run\",\"Test\":\"TestSwiftProof\",\"Package\":\"target\"}\n{\"Action\":\"pass\",\"Test\":\"TestSwiftProof\",\"Package\":\"target\"}\n{\"Action\":\"run\",\"Test\":\"TestSwiftProof\",\"Package\":\"other\"}\n{\"Action\":\"fail\",\"Test\":\"TestSwiftProof\",\"Package\":\"other\"}\n"}
	if ValidateGoExecution(check, []string{"TestSwiftProof"}).Status != "ERROR" {
		t.Fatal("same-named test from different package accepted")
	}
}
