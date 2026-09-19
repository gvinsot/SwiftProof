package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/gvinsot/SwiftProof/internal/config"
	"github.com/gvinsot/SwiftProof/internal/model"
)

// This test uses a scripted provider, real Git commits and real Docker execution.
// It verifies the entire CLI/evidence path without a live AI service or API key.
func TestDockerReviewEndToEnd(t *testing.T) {
	image := os.Getenv("SWIFTPROOF_TEST_DOCKER_IMAGE")
	if image == "" {
		t.Skip("set SWIFTPROOF_TEST_DOCKER_IMAGE to a preloaded Go image")
	}
	dir := fixture(t)
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Messages []struct{ Role, Content string } `json:"messages"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		var name string
		var args any
		switch n := calls.Add(1); n {
		case 1:
			name = "create_test"
			args = map[string]any{"path": "swiftproof_guest_test.go", "description": "Guest authorization must remain rejected", "content": "package fixture\nimport \"testing\"\nfunc TestSwiftProofRejectGuest(t *testing.T) { if Allowed(\"guest\") { t.Fatal(\"guest was authorized\") } }\n"}
		case 2:
			name = "run_generated_test"
			args = map[string]any{"test_id": "generated-test-1"}
		case 3:
			var observation struct {
				Evidence model.Evidence `json:"evidence"`
			}
			if len(request.Messages) == 0 || json.Unmarshal([]byte(request.Messages[len(request.Messages)-1].Content), &observation) != nil || observation.Evidence.ID == "" {
				http.Error(w, "missing real evidence", 500)
				return
			}
			name = "submit_hypothesis"
			args = map[string]any{"title": "Guest is allowed through authorization", "severity": "high", "status": "REPRODUCED", "rationale": "The generated named test passes on the baseline and fails on the candidate.", "evidence_ids": []string{observation.Evidence.ID}, "path": "auth.go", "line": 3}
		default:
			json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"finish_reason": "stop", "message": map[string]any{"role": "assistant", "content": "Investigation completed."}}}})
			return
		}
		arguments, _ := json.Marshal(args)
		json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"finish_reason": "tool_calls", "message": map[string]any{"role": "assistant", "tool_calls": []any{map[string]any{"id": fmt.Sprintf("call-%d", calls.Load()), "type": "function", "function": map[string]any{"name": name, "arguments": string(arguments)}}}}}}})
	}))
	defer server.Close()
	cfg := config.Default("go")
	cfg.Sandbox.Image = image
	cfg.Reviewer.Endpoint = server.URL
	cfg.Reviewer.Model = "scripted-integration"
	cfg.Reviewer.APIKeyEnv = "SWIFTPROOF_INTEGRATION_KEY"
	t.Setenv(cfg.Reviewer.APIKeyEnv, "")
	policy := filepath.Join(t.TempDir(), "policy.json")
	b, _ := json.Marshal(cfg)
	if err := os.WriteFile(policy, b, 0600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	code := Run(context.Background(), []string{"review", "--repo", dir, "--config", policy, "--checks=false", "--reviewer", "--ci", "--out", "report"}, &out, &errOut, "integration")
	if code != 1 {
		t.Fatalf("expected reproduced-issue exit 1; got %d\n%s\n%s", code, out.String(), errOut.String())
	}
	b, err := os.ReadFile(filepath.Join(dir, "report", "confidence-report.json"))
	if err != nil {
		t.Fatal(err)
	}
	var result model.Report
	if err := json.Unmarshal(b, &result); err != nil {
		t.Fatal(err)
	}
	if len(result.ReproducedIssues) != 1 || len(result.Evidence) != 1 || len(result.Checks) != 2 {
		t.Fatalf("missing evidence chain: %+v", result)
	}
	if result.Checks[0].Status != "PASS" || result.Checks[1].Status != "FAIL" || result.Evidence[0].Runner != "go_test_json" {
		t.Fatalf("incorrect differential check: %+v", result.Checks)
	}
	seen := map[string]bool{}
	for _, event := range result.Audit {
		seen[event.Tool] = true
	}
	for _, tool := range []string{"reviewer_completion", "create_test", "run_generated_test", "submit_hypothesis"} {
		if !seen[tool] {
			t.Errorf("missing audit for %s", tool)
		}
	}
	retained := false
	for _, artifact := range result.Artifacts {
		if artifact.Kind == "generated_test" {
			retained = true
			if _, err := os.Stat(filepath.Join(dir, "report", filepath.FromSlash(artifact.Path))); err != nil {
				t.Error(err)
			}
		}
	}
	if !retained {
		t.Fatal("reproducing test was not retained")
	}
	if _, err := os.Stat(filepath.Join(dir, "swiftproof_guest_test.go")); !os.IsNotExist(err) {
		t.Fatal("generated test leaked into checkout")
	}
	if calls.Load() != 4 {
		t.Fatalf("unexpected provider calls %d", calls.Load())
	}
}
