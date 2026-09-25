package reviewer

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/gvinsot/SwiftProof/app/internal/harness"
	"github.com/gvinsot/SwiftProof/app/internal/model"
	reports "github.com/gvinsot/SwiftProof/app/internal/report"
)

// scripted serves the given tool-call batches in order, then a final answer,
// and records every request body.
func scripted(t *testing.T, batches ...[]toolCall) (*httptest.Server, *[]map[string]any) {
	t.Helper()
	var bodies []map[string]any
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		bodies = append(bodies, body)
		requests++
		if requests <= len(batches) {
			complete(w, batches[requests-1]...)
			return
		}
		complete(w)
	}))
	t.Cleanup(server.Close)
	return server, &bodies
}

// A call to a tool outside the offered set is audited under the reserved name
// rejected_tool_call; the model-supplied name, even a forged harness stage name,
// is never an audit tool name.
func TestRejectedToolCallAuditedUnderReservedName(t *testing.T) {
	longName := "stage:run_fuzz\x01" + strings.Repeat("n", 300)
	server, _ := scripted(t, []toolCall{
		call("a", "stage:run_fuzz", `{"note":"forged"}`),
		call("b", "shell", `{"cmd":"`+strings.Repeat("x", 10000)+`"}`),
		call("c", longName, `{}`),
	})
	r := &model.Report{}
	h := &fakeHarness{}
	if err := Run(context.Background(), Options{Endpoint: server.URL, Model: "test"}, r, h); err != nil {
		t.Fatal(err)
	}
	if len(h.calls) != 0 {
		t.Fatalf("rejected tools reached the harness: %v", h.calls)
	}
	var rejected []model.AuditEvent
	for _, e := range r.Audit {
		switch e.Tool {
		case model.AuditRejectedToolCall:
			rejected = append(rejected, e)
		case "reviewer_completion":
		default:
			t.Errorf("audit tool %q taken from the model", e.Tool)
		}
	}
	if len(rejected) != 3 {
		t.Fatalf("%d rejected_tool_call events, want 3: %+v", len(rejected), r.Audit)
	}
	for i, want := range []string{"stage:run_fuzz", "shell", ""} {
		e := rejected[i]
		var args struct {
			RequestedTool string `json:"requested_tool"`
			Arguments     string `json:"arguments"`
		}
		if err := json.Unmarshal([]byte(e.Arguments), &args); err != nil {
			t.Fatalf("audit arguments are not a JSON record: %q", e.Arguments)
		}
		if e.Status != "ERROR" || len(e.Arguments) > 4096 {
			t.Errorf("event %d: status %s, %d bytes", i, e.Status, len(e.Arguments))
		}
		if len(args.RequestedTool) > 128 || !utf8.ValidString(args.RequestedTool) || strings.ContainsAny(args.RequestedTool, "\x00\x01\n") {
			t.Errorf("event %d: requested_tool not bounded or cleaned: %q", i, args.RequestedTool)
		}
		if want != "" && args.RequestedTool != want {
			t.Errorf("event %d: requested_tool %q, want %q", i, args.RequestedTool, want)
		}
	}
	if !strings.HasPrefix(rejected[2].Arguments, `{"arguments":"{}","requested_tool":"stage:run_fuzz`) {
		t.Errorf("long name record %q", rejected[2].Arguments)
	}
	joined := strings.Join(r.Unverified, "\n")
	if !strings.Contains(joined, "Reviewer could not complete tool stage:run_fuzz: tool is not available") {
		t.Fatalf("the Unverified line changed: %q", r.Unverified)
	}
}

func enumOf(t *testing.T, tool map[string]any, property string) []string {
	t.Helper()
	params := tool["function"].(map[string]any)["parameters"].(map[string]any)
	p, ok := params["properties"].(map[string]any)[property].(map[string]any)
	if !ok {
		return nil
	}
	values, _ := p["enum"].([]string)
	return values
}

func TestHypothesisToolStatuses(t *testing.T) {
	required := []string{"title", "severity", "status", "rationale", "evidence_ids", "path", "line"}
	for _, withIntent := range []bool{false, true} {
		tool := hypothesisTool(withIntent)
		params := tool["function"].(map[string]any)["parameters"].(map[string]any)
		if !reflect.DeepEqual(params["required"], required) {
			t.Fatalf("withIntent=%v changed required: %v", withIntent, params["required"])
		}
		statuses := strings.Join(enumOf(t, tool, "status"), ",")
		if !strings.Contains(statuses, model.StatusDiverged) {
			t.Fatalf("withIntent=%v: DIVERGED missing from %s", withIntent, statuses)
		}
		properties := params["properties"].(map[string]any)
		_, hasCriterion := properties["criterion_id"]
		_, hasJudgment := properties["intent_judgment"]
		hasIntentStatus := strings.Contains(statuses, model.StatusIntentTestFailed)
		if hasCriterion != withIntent || hasJudgment != withIntent || hasIntentStatus != withIntent {
			t.Fatalf("withIntent=%v: criterion %v judgment %v INTENT_TEST_FAILED %v", withIntent, hasCriterion, hasJudgment, hasIntentStatus)
		}
		if withIntent {
			if got := strings.Join(enumOf(t, tool, "intent_judgment"), ","); got != "expected_change,unexpected_change" {
				t.Fatalf("intent_judgment enum %s", got)
			}
			description := properties["intent_judgment"].(map[string]any)["description"].(string)
			if !strings.Contains(description, "never evidence") || !strings.Contains(description, "DIVERGED") {
				t.Fatalf("intent_judgment description %q", description)
			}
		}
	}
}

func TestToolDefinitionsOfferIntentToolsOnlyWithCriteria(t *testing.T) {
	all := harness.ToolDefinitions()
	if got := toolDefinitions(true); len(got) != len(all) {
		t.Fatalf("with criteria: %d definitions, want all %d", len(got), len(all))
	}
	for _, d := range toolDefinitions(false) {
		if harness.IsIntentTool(definitionName(d)) {
			t.Fatalf("intent tool %s offered without criteria", definitionName(d))
		}
	}
	names := map[string]bool{}
	for _, d := range toolDefinitions(false) {
		names[definitionName(d)] = true
	}
	for _, d := range all {
		if n := definitionName(d); !harness.IsIntentTool(n) && !names[n] {
			t.Fatalf("tool %s removed without reason", n)
		}
	}
}

// The provider sees intent criteria, the intent status and the extended system
// prompt only when the intent yielded criteria.
func TestRequestReflectsIntentCriteria(t *testing.T) {
	for _, criteria := range [][]model.IntentCriterion{nil, {{ID: "AC-1", Text: "Totals never go negative", Line: 1}}} {
		server, bodies := scripted(t)
		r := &model.Report{Intent: "AC-1: Totals never go negative", IntentCriteria: criteria}
		if err := Run(context.Background(), Options{Endpoint: server.URL, Model: "test"}, r, &fakeHarness{}); err != nil {
			t.Fatal(err)
		}
		body := (*bodies)[0]
		messages := body["messages"].([]any)
		system := messages[0].(map[string]any)["content"].(string)
		user := messages[1].(map[string]any)["content"].(string)
		if !strings.HasPrefix(system, systemPrompt) {
			t.Fatal("system prompt no longer starts with the base prompt")
		}
		if strings.Contains(user, `"intent_criteria"`) != (len(criteria) > 0) {
			t.Fatalf("criteria %v: user message %s", criteria, user)
		}
		encoded, _ := json.Marshal(body["tools"])
		if strings.Contains(string(encoded), model.StatusIntentTestFailed) != (len(criteria) > 0) {
			t.Fatalf("criteria %v: INTENT_TEST_FAILED offered = %v", criteria, !(len(criteria) > 0))
		}
		if !strings.Contains(string(encoded), model.StatusDiverged) {
			t.Fatal("DIVERGED not offered")
		}
	}
}

// DIVERGED is accepted as a claim and still needs verified evidence; an intent
// link without acceptance criteria is refused.
func TestSubmitDivergedAndIntentLinks(t *testing.T) {
	r := &model.Report{}
	if _, err := submit(r, []byte(`{"title":"Values differ","severity":"medium","status":"diverged","rationale":"Observed","evidence_ids":["evidence-9"],"path":"a.go","line":3}`)); err != nil {
		t.Fatalf("DIVERGED claim refused: %v", err)
	}
	if r.Hypotheses[0].Status != model.StatusDiverged {
		t.Fatalf("status %q", r.Hypotheses[0].Status)
	}
	for _, claim := range []string{
		`{"title":"T","severity":"low","status":"DIVERGED","rationale":"R","evidence_ids":["e"],"path":"a.go","line":1,"criterion_id":"AC-1"}`,
		`{"title":"T","severity":"low","status":"DIVERGED","rationale":"R","evidence_ids":["e"],"path":"a.go","line":1,"intent_judgment":"EXPECTED_CHANGE"}`,
		`{"title":"T","severity":"low","status":"PROVEN","rationale":"R","evidence_ids":["e"],"path":"a.go","line":1}`,
	} {
		if _, err := submit(r, []byte(claim)); err == nil {
			t.Fatalf("accepted %s", claim)
		}
	}
	if len(r.Hypotheses) != 1 {
		t.Fatalf("refused claims were recorded: %+v", r.Hypotheses)
	}
	reports.Finalize(r, true)
	if r.Hypotheses[0].Status != model.StatusUnverified || r.ExitCode != 2 {
		t.Fatalf("an unsupported DIVERGED claim finalized as %s, exit %d", r.Hypotheses[0].Status, r.ExitCode)
	}
}

// The initial input carries bounded logs and no structured results for the
// fuzz, base-test, impacted-test and mutation checks, and leaves the report
// itself untouched.
func TestReviewerViewBoundsNewCheckKinds(t *testing.T) {
	long := strings.Repeat("é", 3000) + "TAILMARK"
	r := &model.Report{Checks: []model.Check{
		{ID: "check-1", Kind: "test", Output: long, Results: "kept-results"},
		{ID: "check-2", Kind: model.CheckFuzzBase, Output: long, Results: "fuzz-results"},
		{ID: "check-3", Kind: model.CheckBaseTestHybrid, Output: long, Results: "x"},
		{ID: "check-4", Kind: model.CheckImpactedTestCandidate, Output: long},
		{ID: "check-5", Kind: model.CheckGeneratedBase, Output: long, Results: "generated-results"},
	}, Mutation: &model.Mutation{Status: model.MutationRan, Checks: []model.Check{{ID: "mutation-check-1", Kind: model.CheckMutant, Output: long, Results: "m"}}}}
	view := reviewerView(r)
	for i, c := range view.Checks {
		bounded := i >= 1 && i <= 3
		if bounded != (len(c.Output) <= reviewerLogLimit) || !utf8.ValidString(c.Output) {
			t.Errorf("%s (%s): %d bytes", c.ID, c.Kind, len(c.Output))
		}
		if bounded && c.Results != "" {
			t.Errorf("%s kept structured results", c.ID)
		}
		if !bounded && c.Results != r.Checks[i].Results {
			t.Errorf("%s lost its results", c.ID)
		}
	}
	if m := view.Mutation.Checks[0]; len(m.Output) > reviewerLogLimit || m.Results != "" {
		t.Errorf("mutation check not bounded: %d bytes, results %q", len(m.Output), m.Results)
	}
	if r.Checks[1].Output != long || r.Checks[1].Results != "fuzz-results" || r.Mutation.Checks[0].Output != long {
		t.Fatal("reviewerView modified the report")
	}
	server, bodies := scripted(t)
	if err := Run(context.Background(), Options{Endpoint: server.URL, Model: "test", MaxInputBytes: 2 << 20}, r, &fakeHarness{}); err != nil {
		t.Fatal(err)
	}
	user := (*bodies)[0]["messages"].([]any)[1].(map[string]any)["content"].(string)
	if strings.Count(user, "TAILMARK") != 2 || strings.Contains(user, "fuzz-results") || !strings.Contains(user, "kept-results") {
		t.Fatalf("reviewer input not bounded as specified (%d tail markers)", strings.Count(user, "TAILMARK"))
	}
}
