package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gvinsot/SwiftProof/app/internal/config"
)

// forbidExecution makes any step that could start a container fail the test:
// every exit-3 path must return before it (contract §1.6).
func forbidExecution(t *testing.T) {
	t.Helper()
	previous := executionStarted
	executionStarted = func() { t.Fatalf("a container stage started on an exit-3 path") }
	t.Cleanup(func() { executionStarted = previous })
}

// countExecution counts how often a container stage was about to start.
func countExecution(t *testing.T) *int {
	t.Helper()
	previous := executionStarted
	calls := new(int)
	executionStarted = func() { *calls++ }
	t.Cleanup(func() { executionStarted = previous })
	return calls
}

func TestValidateExecutionFlags(t *testing.T) {
	valid := execFlags{checks: true, impact: true, parallel: 1}
	for _, tc := range []struct {
		name     string
		mode     string
		explicit []string
		mutate   func(*execFlags)
		want     string // "" means accepted
	}{
		{name: "defaults review", mode: "review"},
		{name: "defaults lint", mode: "lint", mutate: func(v *execFlags) { v.checks = false }},
		{name: "lint allows --impact", mode: "lint", explicit: []string{"impact"}, mutate: func(v *execFlags) { v.checks, v.impact = false, false }},
		{name: "lint --base-tests", mode: "lint", explicit: []string{"base-tests"}, want: "lint does not execute sandbox checks; --base-tests applies to review only"},
		{name: "lint --fuzz", mode: "lint", explicit: []string{"fuzz"}, want: "--fuzz applies to review only"},
		{name: "lint --impacted-tests", mode: "lint", explicit: []string{"impacted-tests"}, want: "--impacted-tests applies to review only"},
		{name: "lint --cache-dir", mode: "lint", explicit: []string{"cache-dir"}, want: "--cache-dir applies to review only"},
		{name: "lint --parallel", mode: "lint", explicit: []string{"parallel"}, want: "--parallel applies to review only"},
		{name: "lint --allow-prepare-network", mode: "lint", explicit: []string{"allow-prepare-network"}, want: "--allow-prepare-network applies to review only"},
		{name: "lint --deadline", mode: "lint", explicit: []string{"deadline"}, want: "--deadline applies to review only"},
		{name: "parallel 0", mode: "review", mutate: func(v *execFlags) { v.parallel = 0 }, want: "--parallel must be between 1 and 4"},
		{name: "parallel 1", mode: "review", explicit: []string{"parallel"}},
		{name: "parallel 4", mode: "review", mutate: func(v *execFlags) { v.parallel = 4 }},
		{name: "parallel 5", mode: "review", mutate: func(v *execFlags) { v.parallel = 5 }, want: "--parallel must be between 1 and 4"},
		{name: "parallel without checks has no effect", mode: "review", mutate: func(v *execFlags) { v.parallel, v.checks = 4, false }},
		{name: "deadline 59s", mode: "review", mutate: func(v *execFlags) { v.deadline = 59 * time.Second }, want: "--deadline must be a duration between 1m and 24h"},
		{name: "deadline 1m", mode: "review", mutate: func(v *execFlags) { v.deadline = time.Minute }},
		{name: "deadline 24h", mode: "review", mutate: func(v *execFlags) { v.deadline = 24 * time.Hour }},
		{name: "deadline 24h1s", mode: "review", mutate: func(v *execFlags) { v.deadline = 24*time.Hour + time.Second }, want: "--deadline must be"},
		{name: "deadline negative", mode: "review", mutate: func(v *execFlags) { v.deadline = -time.Minute }, want: "--deadline must be"},
		{name: "explicit deadline 0", mode: "review", explicit: []string{"deadline"}, want: "--deadline must be"},
		{name: "cache dir", mode: "review", mutate: func(v *execFlags) { v.cacheDir = "/var/cache/swiftproof" }},
		{name: "explicit empty cache dir", mode: "review", explicit: []string{"cache-dir"}, want: "--cache-dir must name a directory"},
		{name: "blank cache dir", mode: "review", mutate: func(v *execFlags) { v.cacheDir = "  " }, want: "--cache-dir must name a directory"},
		{name: "cache dir with NUL", mode: "review", mutate: func(v *execFlags) { v.cacheDir = "a\x00b" }, want: "without NUL"},
		{name: "cache dir 4096 bytes", mode: "review", mutate: func(v *execFlags) { v.cacheDir = strings.Repeat("c", 4096) }},
		{name: "cache dir 4097 bytes", mode: "review", mutate: func(v *execFlags) { v.cacheDir = strings.Repeat("c", 4097) }, want: "at most 4096 bytes"},
		{name: "base tests", mode: "review", mutate: func(v *execFlags) { v.baseTests = true }},
		{name: "base tests without checks", mode: "review", mutate: func(v *execFlags) { v.baseTests, v.checks = true, false }, want: "cannot be combined with --checks=false"},
		{name: "impacted tests", mode: "review", mutate: func(v *execFlags) { v.impactedTests = true }},
		{name: "impacted tests without checks", mode: "review", mutate: func(v *execFlags) { v.impactedTests, v.checks = true, false }, want: "cannot be combined with --checks=false"},
		{name: "impacted tests without impact", mode: "review", mutate: func(v *execFlags) { v.impactedTests, v.impact = true, false }, want: "cannot be combined with --impact=false"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := valid
			if tc.mutate != nil {
				tc.mutate(&v)
			}
			explicit := map[string]bool{}
			for _, name := range tc.explicit {
				explicit[name] = true
			}
			err := validateExecutionFlags(tc.mode, explicit, v)
			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("rejected: %v", err)
			case tc.want != "" && err == nil:
				t.Fatalf("accepted, want %q", tc.want)
			case tc.want != "" && !strings.Contains(err.Error(), tc.want):
				t.Fatalf("error %q does not contain %q", err, tc.want)
			}
		})
	}
}

// v04Policy writes a policy file that configures every opt-in v0.4 key, after
// applying edit to its JSON object, and returns its path.
func v04Policy(t *testing.T, image string, edit func(map[string]any)) string {
	t.Helper()
	cfg := config.Default("go")
	cfg.Sandbox.Image = image
	cfg.Fuzz = &config.Fuzz{}
	cfg.Mutation = &config.Mutation{Command: []string{"go", "test", "-json", "{package}"}, MaxMutants: 5, TimeoutSeconds: 30, MaxRuntimeSeconds: 60}
	cfg.Prepare = &config.Prepare{Command: []string{"go", "mod", "download"}, Inputs: []string{"go.mod"}}
	b, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]any
	if err := json.Unmarshal(b, &object); err != nil {
		t.Fatal(err)
	}
	if edit != nil {
		edit(object)
	}
	b, err = json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

// Every exit-3 path of §1.6 and §1.17 returns before a container stage, before
// any report is written, and names the problem.
func TestExitThreeBeforeAnyContainer(t *testing.T) {
	dir := fixture(t)
	absent := "swiftproof.invalid/absent:test-only"
	valid := v04Policy(t, absent, nil)
	badFuzz := v04Policy(t, absent, func(p map[string]any) { p["fuzz"] = map[string]any{"max_inputs": 257} })
	badMutation := v04Policy(t, absent, func(p map[string]any) {
		p["mutation"] = map[string]any{"command": []string{"go", "test", "-json", "-run=X", "{package}"}, "max_mutants": 5, "timeout_seconds": 30, "max_runtime_seconds": 60}
	})
	badPrepare := v04Policy(t, absent, func(p map[string]any) {
		p["prepare"] = map[string]any{"command": []string{"go", "mod", "download"}, "inputs": []string{"../go.mod"}}
	})
	unknownKey := v04Policy(t, absent, func(p map[string]any) { p["prepare"].(map[string]any)["shell"] = true })
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"lint --base-tests=false", []string{"lint", "--base-tests=false"}, "--base-tests applies to review only"},
		{"lint --fuzz", []string{"lint", "--fuzz"}, "--fuzz applies to review only"},
		{"lint --impacted-tests", []string{"lint", "--impacted-tests"}, "--impacted-tests applies to review only"},
		{"lint --cache-dir", []string{"lint", "--cache-dir", filepath.Join(t.TempDir(), "cache")}, "--cache-dir applies to review only"},
		{"lint --parallel", []string{"lint", "--parallel", "1"}, "--parallel applies to review only"},
		{"lint --allow-prepare-network", []string{"lint", "--allow-prepare-network"}, "--allow-prepare-network applies to review only"},
		{"lint --deadline", []string{"lint", "--deadline", "10m"}, "--deadline applies to review only"},
		{"parallel 0", []string{"review", "--parallel", "0"}, "--parallel must be between 1 and 4"},
		{"parallel 5", []string{"review", "--parallel", "5"}, "--parallel must be between 1 and 4"},
		{"parallel not a number", []string{"review", "--parallel", "two"}, ""},
		{"deadline 59s", []string{"review", "--deadline", "59s"}, "--deadline must be"},
		{"deadline 25h", []string{"review", "--deadline", "25h"}, "--deadline must be"},
		{"deadline 0", []string{"review", "--deadline", "0"}, "--deadline must be"},
		{"deadline not a duration", []string{"review", "--deadline", "soon"}, ""},
		{"empty cache dir", []string{"review", "--cache-dir="}, "--cache-dir must name a directory"},
		{"oversized cache dir", []string{"review", "--cache-dir", strings.Repeat("c", 4097)}, "at most 4096 bytes"},
		{"cache dir inside the repository", []string{"review", "--cache-dir", filepath.Join(dir, "cache")}, ""},
		{"base tests without checks", []string{"review", "--base-tests", "--checks=false"}, "cannot be combined with --checks=false"},
		{"impacted tests without checks", []string{"review", "--impacted-tests", "--checks=false"}, "cannot be combined with --checks=false"},
		{"impacted tests without impact", []string{"review", "--impacted-tests", "--impact=false"}, "cannot be combined with --impact=false"},
		{"unknown format", []string{"review", "--format", "markdown,html"}, "unknown report format"},
		{"report url without pr-comment", []string{"review", "--report-url", "https://example.invalid/r"}, "--report-url"},
		{"lint report url", []string{"lint", "--report-url", "https://example.invalid/r"}, "--report-url"},
		{"invalid fuzz policy", []string{"review", "--config", badFuzz}, "fuzz.max_inputs"},
		{"invalid mutation policy", []string{"review", "--config", badMutation}, "mutation.command"},
		{"invalid prepare policy", []string{"review", "--config", badPrepare}, "prepare.inputs"},
		{"unknown prepare field", []string{"review", "--config", unknownKey}, "unknown field"},
		{"invalid policy in lint", []string{"lint", "--config", badFuzz}, "fuzz.max_inputs"},
		{"oversized intent", []string{"review", "--config", valid, "--intent", strings.Repeat("x", 65537)}, "intent exceeds 64 KiB"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			forbidExecution(t)
			out := filepath.Join(t.TempDir(), "report")
			args := append(append([]string{}, tc.args...), "--repo", dir, "--out", out)
			var stdout, stderr bytes.Buffer
			if code := Run(context.Background(), args, &stdout, &stderr, "test"); code != 3 {
				t.Fatalf("exit %d, want 3: %s", code, stderr.String())
			}
			if tc.want != "" && !strings.Contains(stderr.String(), tc.want) {
				t.Fatalf("stderr %q does not contain %q", stderr.String(), tc.want)
			}
			if _, err := os.Stat(out); !os.IsNotExist(err) {
				t.Fatalf("an exit-3 path wrote the report directory: %v", err)
			}
		})
	}
}

// The render command validates the same format and report-URL rules before it
// reads its input.
func TestRenderRejectsReportURLAndUnknownFormat(t *testing.T) {
	for _, args := range [][]string{
		{"report", "--input", "missing.json", "--report-url", "https://example.invalid/r"},
		{"report", "--input", "missing.json", "--format", "html"},
	} {
		var out bytes.Buffer
		if code := Run(context.Background(), args, &out, &out, "test"); code != 3 {
			t.Fatalf("%v: exit %d, want 3: %s", args, code, out.String())
		}
		if strings.Contains(out.String(), "missing.json") {
			t.Fatalf("%v: the input was read before the flags were validated: %s", args, out.String())
		}
	}
}

// Accepted combinations never exit 3: --impact and the network flags are
// accepted on lint, and --parallel is accepted (without effect) with
// --checks=false.
func TestAcceptedFlagCombinations(t *testing.T) {
	dir := fixture(t)
	for _, args := range [][]string{
		{"lint", "--impact=false", "--allow-network", "--no-network", "--format", "json"},
		{"lint", "--impact"},
		{"review", "--checks=false", "--reviewer=false", "--parallel", "4", "--deadline", "24h", "--fuzz=false", "--impact=false", "--allow-prepare-network"},
		{"review", "--checks=false", "--parallel", "2", "--deadline", "1m"},
	} {
		forbidExecution(t)
		var out, errOut bytes.Buffer
		code := Run(context.Background(), append(args, "--repo", dir, "--out", filepath.Join(t.TempDir(), "report")), &out, &errOut, "test")
		if code == 3 {
			t.Fatalf("%v rejected: %s", args, errOut.String())
		}
	}
}
