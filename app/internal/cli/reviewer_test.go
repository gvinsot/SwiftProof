package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gvinsot/SwiftProof/app/internal/config"
	"github.com/gvinsot/SwiftProof/app/internal/model"
)

func TestReviewerActivation(t *testing.T) {
	for _, tc := range []struct {
		name, mode, model string
		flags             []string
		invalidEndpoint   bool
		wantCalls         int32
		wantCode          int
	}{
		{name: "configured review", mode: "review", model: "test-model", wantCalls: 2, wantCode: 2},
		{name: "explicit enable remains supported", mode: "review", model: "test-model", flags: []string{"--reviewer"}, wantCalls: 2, wantCode: 2},
		{name: "explicit disable", mode: "review", model: "test-model", flags: []string{"--reviewer=false"}, wantCode: 2},
		{name: "no configured model", mode: "review", wantCode: 2},
		{name: "explicit enable requires model", mode: "review", flags: []string{"--reviewer"}, wantCode: 3},
		{name: "lint stays offline", mode: "lint", model: "test-model", wantCode: 2},
		{name: "lint rejects explicit enable", mode: "lint", model: "test-model", flags: []string{"--reviewer"}, wantCode: 3},
		{name: "invalid configured provider fails early", mode: "review", model: "test-model", invalidEndpoint: true, wantCode: 3},
		{name: "disabled provider need not be valid", mode: "review", model: "test-model", invalidEndpoint: true, flags: []string{"--reviewer=false"}, wantCode: 2},
		{name: "whitespace model is a configuration error", mode: "review", model: " ", wantCode: 3},
		{name: "empty change skips provider", mode: "review", model: "test-model", flags: []string{"--head", "main"}, wantCode: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := fixture(t)
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var request struct {
					Model string `json:"model"`
				}
				if err := json.NewDecoder(r.Body).Decode(&request); err != nil || request.Model != tc.model {
					t.Errorf("unexpected request model: %q, error: %v", request.Model, err)
				}
				if r.URL.Path != "/v1/chat/completions" || r.Header.Get("Authorization") != "Bearer test-reviewer-key" {
					t.Error("provider URL or authentication was not taken from trusted configuration")
				}
				if calls.Add(1) == 1 {
					// An automatically enabled model still cannot invent evidence.
					w.Write([]byte(`{"choices":[{"finish_reason":"tool_calls","message":{"role":"assistant","tool_calls":[{"id":"claim","type":"function","function":{"name":"submit_hypothesis","arguments":"{\"title\":\"Authorization regression\",\"severity\":\"high\",\"status\":\"REPRODUCED\",\"rationale\":\"Model suspicion without an experiment\",\"evidence_ids\":[\"fabricated\"],\"path\":\"auth.go\",\"line\":3}"}}]}}]}`))
					return
				}
				w.Write([]byte(`{"choices":[{"finish_reason":"stop","message":{"role":"assistant","content":"Done"}}]}`))
			}))
			defer server.Close()
			cfg := config.Default("go")
			cfg.Reviewer.Model = tc.model
			cfg.Reviewer.Endpoint = server.URL + "/v1"
			cfg.Reviewer.APIKeyEnv = "SWIFTPROOF_TEST_REVIEWER_KEY"
			t.Setenv(cfg.Reviewer.APIKeyEnv, "test-reviewer-key")
			if tc.invalidEndpoint {
				cfg.Reviewer.Endpoint = "file:///invalid-provider"
			}
			policy := filepath.Join(t.TempDir(), "policy.json")
			writeReviewerPolicy(t, policy, cfg)
			args := append([]string{tc.mode, "--repo", dir, "--config", policy, "--checks=false", "--ci", "--out", "report"}, tc.flags...)
			var out, errOut bytes.Buffer
			if code := Run(context.Background(), args, &out, &errOut, "test"); code != tc.wantCode {
				t.Fatalf("exit %d, want %d: %s", code, tc.wantCode, errOut.String())
			}
			if got := calls.Load(); got != tc.wantCalls {
				t.Fatalf("provider received %d calls, want %d", got, tc.wantCalls)
			}
			if tc.wantCode == 3 {
				return
			}
			result := readReviewerReport(t, dir)
			if len(result.Checks) != 0 {
				t.Fatal("source investigation unexpectedly executed repository code")
			}
			if tc.wantCalls > 0 && (len(result.Hypotheses) != 1 || result.Hypotheses[0].Status != "UNVERIFIED" || len(result.ReproducedIssues) != 0) {
				t.Fatalf("model claims bypassed evidence validation: %+v", result.Hypotheses)
			}
		})
	}
}

func TestReviewerTrustsOnlySelectedPolicy(t *testing.T) {
	dir := fixture(t)
	var trustedCalls, candidateCalls atomic.Int32
	serve := func(count *atomic.Int32) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			count.Add(1)
			w.Write([]byte(`{"choices":[{"finish_reason":"stop","message":{"role":"assistant","content":"Done"}}]}`))
		}))
	}
	trusted, candidate := serve(&trustedCalls), serve(&candidateCalls)
	defer trusted.Close()
	defer candidate.Close()
	cfg := config.Default("go")
	cfg.Reviewer.Model = "test-model"
	cfg.Reviewer.Endpoint = candidate.URL
	cfg.Reviewer.APIKeyEnv = "SWIFTPROOF_TEST_REVIEWER_KEY"
	t.Setenv(cfg.Reviewer.APIKeyEnv, "") // Local providers may run without a key.
	policy := filepath.Join(dir, config.Filename)
	writeReviewerPolicy(t, policy, cfg)
	git(t, dir, "add", config.Filename)
	git(t, dir, "commit", "-m", "candidate attempts to enable provider")
	args := []string{"review", "--repo", dir, "--checks=false", "--out", "report"}
	var out bytes.Buffer
	if code := Run(context.Background(), args, &out, &out, "test"); code != 0 || candidateCalls.Load() != 0 {
		t.Fatalf("candidate enabled provider: exit %d, calls %d, %s", code, candidateCalls.Load(), out.String())
	}
	git(t, dir, "checkout", "main")
	cfg.Reviewer.Endpoint = trusted.URL
	writeReviewerPolicy(t, policy, cfg)
	git(t, dir, "add", config.Filename)
	git(t, dir, "commit", "-m", "configure trusted reviewer")
	git(t, dir, "checkout", "candidate")
	// Exact comparison selects this new trusted baseline despite branch divergence.
	args = append(args, "--exact")
	if code := Run(context.Background(), args, &out, &out, "test"); code != 0 || trustedCalls.Load() != 1 || candidateCalls.Load() != 0 {
		t.Fatalf("wrong provider selected: exit %d, trusted %d, candidate %d, %s", code, trustedCalls.Load(), candidateCalls.Load(), out.String())
	}
	args = append(args, "--config", policy)
	if code := Run(context.Background(), args, &out, &out, "test"); code != 0 || candidateCalls.Load() != 1 {
		t.Fatalf("explicit local policy ignored: exit %d, calls %d, %s", code, candidateCalls.Load(), out.String())
	}
}

func TestAutomaticReviewerFailurePreservesStaticReport(t *testing.T) {
	dir := fixture(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "private provider diagnostic", http.StatusServiceUnavailable)
	}))
	defer server.Close()
	cfg := config.Default("go")
	cfg.Reviewer.Endpoint, cfg.Reviewer.Model = server.URL, "test-model"
	cfg.Reviewer.APIKeyEnv = "SWIFTPROOF_TEST_REVIEWER_KEY"
	t.Setenv(cfg.Reviewer.APIKeyEnv, "")
	policy := filepath.Join(t.TempDir(), "policy.json")
	writeReviewerPolicy(t, policy, cfg)
	var out bytes.Buffer
	if code := Run(context.Background(), []string{"review", "--repo", dir, "--config", policy, "--checks=false", "--ci", "--out", "report"}, &out, &out, "test"); code != 2 {
		t.Fatalf("incomplete reviewer must request human review: %d, %s", code, out.String())
	}
	r := readReviewerReport(t, dir)
	if len(r.Signals) == 0 || len(r.ReproducedIssues) != 0 || !strings.Contains(strings.Join(r.Unverified, "\n"), "Reviewer incomplete: reviewer endpoint returned HTTP 503") {
		t.Fatalf("failed reviewer lost static results or incomplete status: %+v", r)
	}
}

func writeReviewerPolicy(t *testing.T, path string, cfg config.Config) {
	t.Helper()
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func readReviewerReport(t *testing.T, dir string) model.Report {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "report", "confidence-report.json"))
	if err != nil {
		t.Fatal(err)
	}
	var result model.Report
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

// A deployment points the pinned binary and its trusted policy at its own
// provider: endpoint and model come from the environment, the credential from
// the mounted Docker secret, and a policy that configures no model at all is
// still activated by the deployed model.
func TestReviewerTakesProviderFromDeployment(t *testing.T) {
	dir := fixture(t)
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Model string `json:"model"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil || request.Model != "deployed-model" {
			t.Errorf("request model is %q, error %v; want the deployed model", request.Model, err)
		}
		if r.URL.Path != "/v1/chat/completions" || r.Header.Get("Authorization") != "Bearer secret-key" {
			t.Error("endpoint or credential was not taken from the deployment")
		}
		calls.Add(1)
		w.Write([]byte(`{"choices":[{"finish_reason":"stop","message":{"role":"assistant","content":"Done"}}]}`))
	}))
	defer server.Close()
	cfg := config.Default("go")
	cfg.Reviewer.Endpoint, cfg.Reviewer.Model = "https://unreachable.invalid/v1", ""
	cfg.Reviewer.APIKeyEnv = "SWIFTPROOF_TEST_REVIEWER_KEY"
	policy := filepath.Join(t.TempDir(), "policy.json")
	writeReviewerPolicy(t, policy, cfg)
	// The deployment converts the variable into a secret and removes it from
	// the container environment, leaving only the mounted file behind.
	secret := filepath.Join(t.TempDir(), "SWIFTPROOF_TEST_REVIEWER_KEY")
	if err := os.WriteFile(secret, []byte("secret-key\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(cfg.Reviewer.APIKeyEnv, "")
	t.Setenv(cfg.Reviewer.APIKeyEnv+config.FileEnvSuffix, secret)
	t.Setenv(config.EndpointEnv, server.URL+"/v1")
	t.Setenv(config.ModelEnv, "deployed-model")
	args := []string{"review", "--repo", dir, "--config", policy, "--checks=false", "--ci", "--out", "report"}
	var out, errOut bytes.Buffer
	if code := Run(context.Background(), args, &out, &errOut, "test"); code != 2 || calls.Load() != 1 {
		t.Fatalf("exit %d with %d provider calls, want 2 and 1: %s", code, calls.Load(), errOut.String())
	}
	if !strings.Contains(errOut.String(), "model from "+config.ModelEnv) || strings.Contains(errOut.String(), "secret-key") {
		t.Fatalf("the run log must name the deployed sources without the credential: %s", errOut.String())
	}
	// A named secret that cannot be read stops the run instead of quietly
	// downgrading it to an unauthenticated request.
	t.Setenv(cfg.Reviewer.APIKeyEnv+config.FileEnvSuffix, secret+".absent")
	if code := Run(context.Background(), args, &out, &errOut, "test"); code != 3 || calls.Load() != 1 {
		t.Fatalf("missing secret: exit %d with %d provider calls, want 3 and 1", code, calls.Load())
	}
}
