package harness

// v0.4 foundation changes to Call, the tool list, New and the results channel.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gvinsot/SwiftProof/app/internal/model"
	"github.com/gvinsot/SwiftProof/app/internal/redact"
)

type fakeIndex struct {
	value            any
	found            bool
	err              error
	tool, symbol     string
	depth, callCount int
}

func (f *fakeIndex) Query(_ context.Context, tool, symbol string, depth int) (any, bool, error) {
	f.callCount++
	f.tool, f.symbol, f.depth = tool, symbol, depth
	return f.value, f.found, f.err
}

func TestNewValidatesFoundationOptions(t *testing.T) {
	src := t.TempDir()
	for _, opts := range []Options{
		{CandidateDir: src, Parallel: 5},
		{CandidateDir: src, Parallel: -1},
		{CandidateDir: src, ReviewerReserve: -time.Second},
		{CandidateDir: src, MaxRuntime: time.Minute, ReviewerReserve: 2 * time.Minute},
	} {
		if h, err := New(opts); err == nil {
			h.Close()
			t.Errorf("accepted %+v", opts)
		}
	}
	criteria := []model.IntentCriterion{{ID: "AC-1", Text: "Totals include tax", Line: 3}}
	h, err := New(Options{CandidateDir: src, Parallel: 4, MaxRuntime: time.Minute, ReviewerReserve: 30 * time.Second, IntentCriteria: criteria, Cache: newMemoryCache(), Symbols: &fakeIndex{}})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	criteria[0].Text = "changed by the caller"
	if h.opts.IntentCriteria[0].Text != "Totals include tax" {
		t.Fatal("New keeps the caller's criteria slice")
	}
	if h.exec.cache == nil {
		t.Fatal("the configured cache was not kept")
	}
	if b := h.Budget(); b.ReviewerReserveMS != 30000 || b.MaxRuntimeMS != 60000 {
		t.Fatalf("budget %+v", b)
	}
	if e := h.Execution(); e.Budget != h.Budget() {
		t.Fatalf("stub Execution %+v", e)
	}
}

func TestCallArgumentScoping(t *testing.T) {
	h := fixture(t)
	for _, tc := range []struct{ tool, args, want string }{
		{"create_test", `{"path":"pkg/x_test.go","content":"x","criterion_id":"AC-1"}`, "criterion_id is accepted only by create_intent_test"},
		{"run_generated_test", `{"test_id":"x","criterion_id":"AC-1"}`, "criterion_id is accepted only by create_intent_test"},
		{"find_references", `{"symbol":"Value","depth":2}`, "depth is accepted only by find_callers"},
		{"inspect_symbol", `{"symbol":"Value","depth":1}`, "depth is accepted only by find_callers"},
		{"find_callers", `{"symbol":"Value","depth":4}`, "depth must be between 1 and 3"},
		{"find_callers", `{"symbol":"Value","depth":-1}`, "depth must be between 1 and 3"},
		{IntentCreateTool, `{"criterion_id":"AC-1","path":"pkg/x_test.go","content":"x"}`, "intent tests require acceptance criteria"},
		{IntentRunTool, `{"test_id":"intent-test-1"}`, "intent tests require acceptance criteria"},
	} {
		_, err := h.Call(context.Background(), tc.tool, json.RawMessage(tc.args))
		if err == nil || err.Error() != tc.want {
			t.Errorf("%s %s: %v, want %q", tc.tool, tc.args, err, tc.want)
		}
	}
	// The intent audit never keeps the test source.
	for _, e := range h.Audit() {
		if e.Tool == IntentCreateTool && (strings.Contains(e.Arguments, "content") || !strings.Contains(e.Arguments, "AC-1")) {
			t.Fatalf("intent audit %q", e.Arguments)
		}
	}
}

func TestSymbolToolsUseTheIndexThenFallBack(t *testing.T) {
	h := fixture(t)
	index := &fakeIndex{value: map[string]any{"callers": []string{"pkg.Caller"}, "method": "static index"}, found: true}
	h.opts.Symbols = index
	out := call(t, h, "find_callers", map[string]any{"symbol": "Value"})
	if index.tool != "find_callers" || index.symbol != "Value" || index.depth != 1 || !strings.Contains(string(out), "pkg.Caller") {
		t.Fatalf("find_callers default depth: %+v %s", index, out)
	}
	call(t, h, "find_callers", map[string]any{"symbol": "Value", "depth": 3})
	if index.depth != 3 {
		t.Fatalf("depth %d", index.depth)
	}
	call(t, h, "inspect_symbol", map[string]any{"symbol": "Value"})
	if index.tool != "inspect_symbol" || index.depth != 0 {
		t.Fatalf("inspect_symbol forwarded %+v", index)
	}
	index.found = false
	out = call(t, h, "find_references", map[string]any{"symbol": "Value"})
	if !strings.Contains(string(out), "lexical") || !strings.Contains(string(out), "pkg/main.go") {
		t.Fatalf("no lexical fallback: %s", out)
	}
	index.err = errors.New("index unavailable")
	if _, err := h.Call(context.Background(), "find_references", json.RawMessage(`{"symbol":"Value"}`)); err == nil {
		t.Fatal("index error hidden")
	}
	h.opts.Symbols = nil
	out = call(t, h, "find_callers", map[string]any{"symbol": "Value", "depth": 2})
	if !strings.Contains(string(out), "lexical") {
		t.Fatalf("no index: %s", out)
	}
	calls := index.callCount
	if _, err := h.Call(context.Background(), "find_callers", json.RawMessage(`{"symbol":""}`)); err == nil || index.callCount != calls {
		t.Fatal("an empty symbol was queried")
	}
}

func TestRejectedToolNamesNeverBecomeAuditTools(t *testing.T) {
	h := fixture(t)
	for _, name := range []string{"shell", "stage:prepare", "stage:execution_cache", "run_" + strings.Repeat("x", 300), "bad\nname"} {
		if _, err := h.Call(context.Background(), name, json.RawMessage(`{"query":"password=hidden"}`)); err == nil {
			t.Fatalf("%q accepted", name)
		}
	}
	for _, e := range h.Audit() {
		if e.Tool != model.AuditRejectedToolCall || e.Status != "ERROR" {
			t.Fatalf("audit %+v", e)
		}
		var args map[string]string
		if err := json.Unmarshal([]byte(e.Arguments), &args); err != nil {
			t.Fatalf("audit arguments %q: %v", e.Arguments, err)
		}
		if args["requested_tool"] == "" || len(args["requested_tool"]) > 128 || strings.ContainsAny(args["requested_tool"], "\n") || strings.Contains(e.Arguments, "hidden") {
			t.Fatalf("audit arguments %+v", args)
		}
	}
	if len(h.Audit()) != 5 {
		t.Fatalf("audit %+v", h.Audit())
	}
}

func TestToolDefinitionsAddFindCallers(t *testing.T) {
	names := map[string]map[string]any{}
	for _, d := range ToolDefinitions() {
		fn := d["function"].(map[string]any)
		names[fn["name"].(string)] = fn
	}
	fc, ok := names["find_callers"]
	if !ok {
		t.Fatal("find_callers missing")
	}
	params := fc["parameters"].(map[string]any)
	depth := params["properties"].(map[string]any)["depth"].(map[string]any)
	if depth["type"] != "integer" || depth["minimum"] != 1 || depth["maximum"] != 3 || fmt.Sprint(params["required"]) != "[symbol]" {
		t.Fatalf("find_callers schema %+v", params)
	}
	for _, name := range []string{"find_references", "inspect_symbol", "find_callers"} {
		d := strings.ToLower(names[name]["description"].(string))
		for _, want := range []string{"approximate", "possible dispatch", "not proof of absence", "lexical"} {
			if !strings.Contains(d, want) {
				t.Errorf("%s description lacks %q: %s", name, want, d)
			}
		}
		for _, word := range []string{"complete", "all callers", "verified", "safe"} {
			if strings.Contains(d, word) {
				t.Errorf("%s description claims %q", name, word)
			}
		}
	}
	for name := range names {
		if IsIntentTool(name) {
			t.Errorf("the stub offers intent tool %s", name)
		}
		if strings.Contains(name, ":") {
			t.Errorf("tool name %q contains ':'", name)
		}
		if !knownTools[name] {
			t.Errorf("published tool %q is not dispatched by Call", name)
		}
	}
	if !IsIntentTool(IntentCreateTool) || !IsIntentTool(IntentRunTool) || IsIntentTool("create_test") {
		t.Fatal("IsIntentTool")
	}
}

func TestRetainedTestsRefusalAndIntentGuard(t *testing.T) {
	h := fixture(t)
	calls := 0
	h.execute = func(_ context.Context, _ string, _ []string, out io.Writer) execution {
		calls++
		if calls == 1 {
			writeGoEvents(out, "pass")
			return execution{ExitCode: 0}
		}
		writeGoEvents(out, "fail")
		return execution{ExitCode: 1}
	}
	call(t, h, "create_test", map[string]any{"path": "pkg/regression_test.go", "content": generatedSource})
	var result map[string]any
	if err := json.Unmarshal(call(t, h, "run_generated_test", map[string]any{"test_id": "generated-test-1"}), &result); err != nil {
		t.Fatal(err)
	}
	if _, ok := result["observation"]; ok {
		t.Fatal("the observation stub added a result field")
	}
	e := result["evidence"].(map[string]any)
	if e["id"] != "evidence-1" || e["status"] != model.StatusReproduced || e["base_check_id"] != "check-1" || e["check_id"] != "check-2" {
		t.Fatalf("evidence %+v", e)
	}
	_, err := h.Call(context.Background(), "delete_generated_test", json.RawMessage(`{"test_id":"generated-test-1"}`))
	if err == nil || err.Error() != "tests that reproduced an issue, recorded a divergence or failed as an intent test are retained as evidence" {
		t.Fatalf("refusal %v", err)
	}
	// An intent test never runs through the differential tool.
	h.tests["generated-test-9"] = &generatedTest{ID: "generated-test-9", Path: "pkg/intent_test.go", Content: generatedSource, Criterion: "AC-1", GoTests: []string{"TestSwiftProof"}}
	before := calls
	if _, err := h.Call(context.Background(), "run_generated_test", json.RawMessage(`{"test_id":"generated-test-9"}`)); err == nil || !strings.Contains(err.Error(), "use run_intent_test") || calls != before {
		t.Fatalf("intent test ran differentially: %v", err)
	}
}

func TestDifferentialStatus(t *testing.T) {
	pass, fail, errCheck := model.Check{Status: "PASS"}, model.Check{Status: "FAIL"}, model.Check{Status: "ERROR"}
	for _, tc := range []struct {
		runner          string
		base, candidate model.Check
		want            string
	}{
		{RunnerGo, pass, fail, model.StatusReproduced},
		{RunnerJest, pass, pass, model.StatusNotReproduced},
		{"", pass, fail, model.StatusUnverified},
		{RunnerGo, fail, fail, model.StatusUnverified},
		{RunnerGo, pass, errCheck, model.StatusUnverified},
		{RunnerGo, errCheck, pass, model.StatusUnverified},
	} {
		if got := differentialStatus(tc.runner, tc.base, tc.candidate); got != tc.want {
			t.Errorf("%s %s/%s: %s, want %s", tc.runner, tc.base.Status, tc.candidate.Status, got, tc.want)
		}
	}
}

func TestRedactWrappersMatchTheLeafPackage(t *testing.T) {
	for _, s := range []string{"plain", "password=hunter2", "://0:://0:0@@", "Bearer abc.def-ghi", "a\n-----BEGIN RSA PRIVATE KEY-----\nx\n"} {
		if Redact(s) != redact.Redact(s) || Redact(Redact(s)) != Redact(s) {
			t.Errorf("Redact(%q) is not the idempotent leaf redaction", s)
		}
	}
	if truncateUTF8("héllo", 2) != redact.TruncateUTF8("héllo", 2) || truncateUTF8("héllo", 2) != "h" {
		t.Fatal("truncateUTF8 wrapper")
	}
}

// --- results channel ----------------------------------------------------------

func TestNormalizedJestReportRedactsEveryKeptString(t *testing.T) {
	raw := `{"testResults":[{"name":"/workspace/src/password=hunter2.test.ts","status":"failed","message":"api_key=abcdef","assertionResults":[{"ancestorTitles":["token Bearer abcdefghijklmnop"],"title":"uses secret=s3cr3t","status":"failed","failureMessages":["Bearer zyxwvutsrqponm"]}]}]}`
	got, err := normalizeJestReport([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{"hunter2", "abcdef\"", "abcdefghijklmnop", "s3cr3t", "zyxwvutsrqponm"} {
		if strings.Contains(got, leak) {
			t.Errorf("normalized report keeps %q: %s", leak, got)
		}
	}
	if !redact.IsFixedPoint(got) {
		t.Fatalf("normalized report is not a fixed point: %s", got)
	}
}

func TestResultsThatAreNotARedactFixedPointAreRejected(t *testing.T) {
	// Each string is clean on its own, but the encoded report reads as a URL
	// with credentials across the title and status fields.
	report := `{"testResults":[{"name":"/workspace/src/cart.test.ts","assertionResults":[{"ancestorTitles":[],"title":"http://user","status":"pa@ss"}]}]}`
	normalized, err := normalizeJestReport([]byte(report))
	if err != nil {
		t.Fatal(err)
	}
	if redact.IsFixedPoint(normalized) {
		t.Fatalf("the fixture no longer exercises the fixed-point rule: %s", normalized)
	}
	h := tsFixture(t)
	h.executeCapture = func(_ context.Context, _ string, _ []string, _, payload io.Writer) execution {
		fmt.Fprint(payload, coverageFrame(report))
		return execution{ExitCode: 0}
	}
	h.mu.Lock()
	c := h.runWithResultsOptions(context.Background(), model.CheckGeneratedBase, h.base, h.testCommand("src/cart.test.ts"), runOptions{})
	h.mu.Unlock()
	if c.Status != "ERROR" || c.Results != "" || !strings.Contains(c.Output, "redaction would alter") {
		t.Fatalf("unreadable results accepted: %+v", c)
	}
	if got := h.Checks()[0]; got.Status != "ERROR" || got.Results != "" {
		t.Fatalf("ledger %+v", got)
	}
	if _, ok := artifactByKind(h, model.ArtifactTestResults); ok {
		t.Fatal("unreadable results were retained as test results")
	}
}

func TestResultsBeyondTheReportBudgetAreArtifactOnly(t *testing.T) {
	h := tsFixture(t)
	report := jestResults("src/cart.test.ts", map[string]string{"applies the discount once": "passed"})
	normalized, err := normalizeJestReport([]byte(report))
	if err != nil {
		t.Fatal(err)
	}
	h.executeCapture = func(_ context.Context, _ string, _ []string, _, payload io.Writer) execution {
		fmt.Fprint(payload, coverageFrame(report))
		return execution{ExitCode: 0}
	}
	run := func() model.Check {
		h.mu.Lock()
		defer h.mu.Unlock()
		return h.runWithResultsOptions(context.Background(), model.CheckGeneratedBase, h.base, h.testCommand("src/cart.test.ts"), runOptions{})
	}
	h.mu.Lock()
	h.resultsBytes = ResultsBudget - len(normalized)
	h.mu.Unlock()
	if c := run(); c.Status != "PASS" || c.Results != normalized {
		t.Fatalf("results that exactly fit were refused: %+v", c)
	}
	h.mu.Lock()
	if h.resultsBytes != ResultsBudget {
		t.Fatalf("results budget %d", h.resultsBytes)
	}
	h.mu.Unlock()
	c := run()
	if c.Status != "ERROR" || c.Results != "" || !strings.Contains(c.Output, resultsOverBudget) {
		t.Fatalf("over-budget results: %+v", c)
	}
	var retained []model.Artifact
	for _, a := range h.Artifacts() {
		if a.Kind == model.ArtifactTestResults && strings.HasSuffix(a.Path, c.ID+"-results.json") {
			retained = append(retained, a)
		}
	}
	if len(retained) != 1 {
		t.Fatalf("over-budget results were not kept as an artifact: %+v", h.Artifacts())
	}
	if b, err := os.ReadFile(retained[0].Path); err != nil || string(b) != normalized {
		t.Fatalf("retained results %q %v", b, err)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.resultsBytes != ResultsBudget {
		t.Fatalf("an artifact-only result was charged: %d", h.resultsBytes)
	}
}

func TestRunWithResultsKeepsTheV02Behavior(t *testing.T) {
	h := tsFixture(t)
	h.executeCapture = func(_ context.Context, _ string, args []string, _, payload io.Writer) execution {
		if !contains(args, "--outputFile="+ResultsPath) {
			t.Errorf("results path not expanded: %q", args)
		}
		fmt.Fprint(payload, coverageFrame(jestResults("src/cart.test.ts", map[string]string{"t": "passed"})))
		return execution{ExitCode: 0}
	}
	h.mu.Lock()
	c := h.runWithResults(context.Background(), "existing_test", h.candidate, h.testCommand("src/cart.test.ts"))
	h.mu.Unlock()
	if c.Status != "PASS" || c.Results == "" || c.Cache != nil {
		t.Fatalf("check %+v", c)
	}
	if _, err := os.Stat(filepath.Join(h.opts.ArtifactDir, h.runID+"-check-1-results.json")); err != nil {
		t.Fatal(err)
	}
}
