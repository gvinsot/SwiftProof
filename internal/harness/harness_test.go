package harness

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/gvinsot/SwiftProof/internal/model"
)

const generatedSource = `package pkg
import "testing"
func TestSwiftProof(t *testing.T) {}
`

func writeGoEvents(w io.Writer, action string) {
	fmt.Fprintln(w, `{"Action":"run","Test":"TestSwiftProof"}`)
	fmt.Fprintf(w, "{\"Action\":%q,\"Test\":\"TestSwiftProof\"}\n", action)
}

func fixture(t *testing.T) *Harness {
	t.Helper()
	src, base := t.TempDir(), t.TempDir()
	for _, dir := range []string{src, base} {
		if err := os.MkdirAll(filepath.Join(dir, "pkg"), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "pkg", "main.go"), []byte("package pkg\nfunc Value() int { return 42 }\n"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	h, err := New(Options{CandidateDir: src, BaseDir: base, ArtifactDir: t.TempDir(), Image: "test-image:local", MaxGeneratedTests: 10, Commands: map[string][]string{"test": {"go", "test", "./..."}, "generated_test": {"go", "test", "{package}"}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.Close() })
	return h
}

func call(t *testing.T, h *Harness, tool string, args any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	out, err := h.Call(context.Background(), tool, b)
	if err != nil {
		t.Fatalf("%s: %v", tool, err)
	}
	return out
}

func TestSnapshotOmitsSecretsAndSymlinks(t *testing.T) {
	src := t.TempDir()
	outside := t.TempDir()
	for _, name := range []string{"safe.go", ".env", "key.pem", "credentials.json"} {
		if err := os.WriteFile(filepath.Join(src, name), []byte("secret material"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	_ = os.Symlink(outside, filepath.Join(src, "escape"))
	h, err := New(Options{CandidateDir: src, ArtifactDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	entries, err := os.ReadDir(h.candidate)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "safe.go" {
		t.Fatalf("unsafe snapshot contents: %v", entries)
	}
	if err := os.WriteFile(filepath.Join(h.candidate, "safe.go"), []byte("changed"), 0644); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(src, "safe.go"))
	if string(b) != "secret material" {
		t.Fatal("snapshot mutated user source")
	}
}

func TestPathsCannotEscapeOrReadSecrets(t *testing.T) {
	h := fixture(t)
	for _, path := range []string{"../outside", "/etc/passwd", "C:/Windows/system.ini", `..\outside`, ".env", "nested/.env.production", ".aws/credentials", "id_ed25519", "pkg/secret.key", ""} {
		if _, err := safePath(h.candidate, path); err == nil {
			t.Errorf("accepted unsafe path %q", path)
		}
	}
	if err := os.Symlink(t.TempDir(), filepath.Join(h.candidate, "link")); err == nil {
		if _, err := safePath(h.candidate, "link/file.go"); err == nil {
			t.Error("accepted symlink parent")
		}
	}
	if _, err := safePath(h.candidate, "pkg/main.go"); err != nil {
		t.Fatal(err)
	}
}

func TestDockerIsolationAndArgvPreservation(t *testing.T) {
	h := fixture(t)
	command := []string{"go", "test", "; touch /source/pwned", `$(echo attack)`}
	args := h.dockerArgs("name", h.candidate, command)
	for _, required := range []string{"--read-only", "--pull=never", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--pids-limit=128", "--user=65534:65534", "--memory=1024m", "--memory-swap=1024m", "--cpus=2", "--env=GOPROXY=off", "type=bind,src=" + h.candidate + ",dst=/source,readonly"} {
		if !contains(args, required) {
			t.Errorf("missing isolation option %s", required)
		}
	}
	for _, required := range []string{"/workspace:rw,exec,nosuid,nodev,mode=1777,size=1024m", "/tmp:rw,exec,nosuid,nodev,mode=1777,size=1024m"} {
		if !contains(args, required) {
			t.Errorf("sandbox cannot execute compiled test binaries: missing %s", required)
		}
	}
	for i, arg := range args {
		if arg == "--network" && args[i+1] != "none" {
			t.Error("network enabled by default")
		}
		if arg == "--privileged" || arg == "--env-file" {
			t.Error("unsafe argument")
		}
	}
	if !reflect.DeepEqual(args[len(args)-len(command):], command) {
		t.Fatal("command arguments reinterpreted")
	}
	if !contains(args, `cp -R /source/. /workspace/ && exec "$@"`) {
		t.Error("missing fixed argument-preserving entrypoint")
	}
}

func contains(list []string, item string) bool {
	for _, s := range list {
		if s == item {
			return true
		}
	}
	return false
}

func TestMissingImageNeverExecutesHost(t *testing.T) {
	h := fixture(t)
	h.opts.Image = ""
	called := false
	h.execute = func(context.Context, string, []string, io.Writer) execution { called = true; return execution{} }
	c := h.Run(context.Background(), "test")
	if called || c.Status != "SKIPPED" {
		t.Fatalf("unexpected execution: %+v", c)
	}
}

func TestBoundedRedactedOutputAndArtifacts(t *testing.T) {
	h := fixture(t)
	h.opts.MaxOutputBytes = 256
	h.execute = func(_ context.Context, _ string, _ []string, out io.Writer) execution {
		fmt.Fprint(out, "password=super-secret\n", strings.Repeat("x", 10000))
		return execution{ExitCode: 1}
	}
	c := h.Run(context.Background(), "test")
	if c.Status != "FAIL" || !c.Truncated || len(c.Output) > 256 || strings.Contains(c.Output, "super-secret") {
		t.Fatalf("unsafe output: %+v", c)
	}
	artifacts := h.Artifacts()
	if len(artifacts) != 1 {
		t.Fatalf("missing artifact: %v", artifacts)
	}
	b, err := os.ReadFile(artifacts[0].Path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	if artifacts[0].SHA256 != hex.EncodeToString(sum[:]) {
		t.Error("artifact hash mismatch")
	}
}

func TestDifferentialEvidenceRequiresBasePass(t *testing.T) {
	cases := []struct {
		name            string
		base, candidate execution
		want            string
	}{
		{"regression", execution{ExitCode: 0}, execution{ExitCode: 1}, "REPRODUCED"},
		{"passing", execution{ExitCode: 0}, execution{ExitCode: 0}, "NOT_REPRODUCED"},
		{"preexisting", execution{ExitCode: 1}, execution{ExitCode: 1}, "UNVERIFIED"},
		{"base_timeout", execution{TimedOut: true, ExitCode: -1}, execution{ExitCode: 1}, "UNVERIFIED"},
		{"candidate_timeout", execution{ExitCode: 0}, execution{TimedOut: true, ExitCode: -1}, "UNVERIFIED"},
		{"docker_error", execution{ExitCode: 0}, execution{ExitCode: 125}, "UNVERIFIED"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := fixture(t)
			calls := 0
			h.execute = func(_ context.Context, _ string, args []string, out io.Writer) execution {
				calls++
				if !reflect.DeepEqual(args[len(args)-7:], []string{"go", "test", "./pkg", "-json", "-count=1", "-run", "^(TestSwiftProof)$"}) {
					t.Fatalf("wrong generated command %v", args)
				}
				for _, dir := range []string{h.base, h.candidate} {
					if _, err := os.Stat(filepath.Join(dir, "pkg", "regression_test.go")); err != nil {
						t.Fatal("test missing from snapshot")
					}
				}
				if calls == 1 {
					if tc.base.ExitCode == 0 {
						writeGoEvents(out, "pass")
					} else if tc.base.ExitCode == 1 {
						writeGoEvents(out, "fail")
					}
					return tc.base
				}
				if tc.candidate.ExitCode == 0 {
					writeGoEvents(out, "pass")
				} else if tc.candidate.ExitCode == 1 {
					writeGoEvents(out, "fail")
				}
				return tc.candidate
			}
			call(t, h, "create_test", map[string]any{"path": "pkg/regression_test.go", "content": generatedSource, "description": "Value stays valid"})
			call(t, h, "run_generated_test", map[string]any{"test_id": "generated-test-1"})
			e := h.Evidence()
			if len(e) != 1 || e[0].Status != tc.want {
				t.Fatalf("wrong evidence: %+v", e)
			}
			if e[0].BaseCheckID != "check-1" || e[0].CheckID != "check-2" {
				t.Error("missing check provenance")
			}
			for _, dir := range []string{h.base, h.candidate} {
				if _, err := os.Stat(filepath.Join(dir, "pkg", "regression_test.go")); !os.IsNotExist(err) {
					t.Error("generated test was not removed")
				}
			}
			_, err := h.Call(context.Background(), "delete_generated_test", json.RawMessage(`{"test_id":"generated-test-1"}`))
			if tc.want == "REPRODUCED" {
				if err == nil {
					t.Error("deleted reproducer")
				}
				if len(h.Artifacts()) != 3 {
					t.Fatal("reproducer artifact missing")
				}
			} else if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestGeneratedTestsCannotOverwriteOrResetBudget(t *testing.T) {
	h := fixture(t)
	h.opts.MaxGeneratedTests = 1
	for _, path := range []string{"pkg/main.go", "../evil_test.go", ".env_test.go", "pkg/main_test.go/../main.go"} {
		if _, err := h.createTest(path, "content", ""); err == nil {
			t.Errorf("accepted %s", path)
		}
	}
	if err := os.WriteFile(filepath.Join(h.candidate, "existing_test.go"), []byte("existing"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := h.createTest("existing_test.go", "replacement", ""); err == nil {
		t.Error("overwrote existing test")
	}
	call(t, h, "create_test", map[string]any{"path": "new_test.go", "content": generatedSource})
	call(t, h, "delete_generated_test", map[string]any{"test_id": "generated-test-1"})
	if _, err := h.createTest("newer_test.go", "package main", ""); err == nil {
		t.Error("deletion reset test budget")
	}
	h.opts.MaxGeneratedTests = 0
	if _, err := h.createTest("disabled_test.go", "package main", ""); err == nil {
		t.Error("zero budget allowed tests")
	}
}

func TestToolAuditAndSecretRedaction(t *testing.T) {
	h := fixture(t)
	if err := os.WriteFile(filepath.Join(h.candidate, "pkg", "config.go"), []byte("package pkg\npassword=super-secret\nfunc Valid() {}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	out := call(t, h, "read_file", map[string]any{"path": "pkg/config.go"})
	if strings.Contains(string(out), "super-secret") {
		t.Fatal("tool leaked secret")
	}
	_, err := h.Call(context.Background(), "shell", json.RawMessage(`{"query":"password=hidden"}`))
	if err == nil {
		t.Fatal("unknown tool accepted")
	}
	_, err = h.Call(context.Background(), "read_file", json.RawMessage(`{"path":"pkg/config.go","command":"rm -rf /"}`))
	if err == nil {
		t.Fatal("unexpected argument accepted")
	}
	audit := h.Audit()
	if len(audit) != 3 || audit[1].Status != "ERROR" || strings.Contains(audit[1].Arguments, "hidden") {
		t.Fatalf("unsafe audit: %+v", audit)
	}
	s := "before\n-----BEGIN PRIVATE KEY-----\nabc\ndef\n-----END PRIVATE KEY-----\nafter"
	redacted := Redact(s)
	if strings.Contains(redacted, "abc") || strings.Count(s, "\n") != strings.Count(redacted, "\n") {
		t.Fatal("redaction leaked key or changed line numbering")
	}
}

func TestRuntimeBudgetAndTimeout(t *testing.T) {
	h := fixture(t)
	h.opts.Timeout = time.Millisecond
	h.opts.MaxRuntime = time.Millisecond
	h.execute = func(ctx context.Context, _ string, _ []string, _ io.Writer) execution {
		<-ctx.Done()
		return execution{ExitCode: -1, TimedOut: true}
	}
	if c := h.Run(context.Background(), "test"); c.Status != "TIMEOUT" {
		t.Fatalf("got %s", c.Status)
	}
	if c := h.Run(context.Background(), "test"); c.Status != "SKIPPED" {
		t.Fatalf("budget allowed more execution: %s", c.Status)
	}
}

func TestSanitizeDiffDropsSensitiveFiles(t *testing.T) {
	diff := "diff --git a/.env b/.env\n+RAW_PRIVATE_SECRET\ndiff --git a/main.go b/main.go\n+func Main(){}\n"
	s := SanitizeDiff(diff)
	if strings.Contains(s, "RAW_PRIVATE_SECRET") || !strings.Contains(s, "func Main") {
		t.Fatal(s)
	}
}

func TestJSONDiffFilteringAndSourceEvidence(t *testing.T) {
	h := fixture(t)
	change := model.Change{Files: []model.ChangedFile{
		{Path: ".env", Hunks: []model.Hunk{{Lines: []model.DiffLine{{Content: "TOP_SECRET"}}}}},
		{Path: "pkg/main.go", Hunks: []model.Hunk{{Lines: []model.DiffLine{{Content: `password="hidden"`}}}}},
	}}
	b, _ := json.Marshal(change)
	h.opts.Diff = string(b)
	out := call(t, h, "get_diff", map[string]any{})
	if strings.Contains(string(out), "TOP_SECRET") || strings.Contains(string(out), "hidden") {
		t.Fatalf("diff secret leak: %s", out)
	}
	out = call(t, h, "get_diff", map[string]any{"path": "pkg/main.go"})
	if strings.Contains(string(out), ".env") || !strings.Contains(string(out), "pkg/main.go") {
		t.Fatalf("diff not filtered: %s", out)
	}
	out = call(t, h, "read_file", map[string]any{"path": "pkg/main.go"})
	if !strings.Contains(string(out), "evidence-1") {
		t.Fatalf("missing observation evidence: %s", out)
	}
	e := h.Evidence()
	if len(e) != 1 || e[0].Kind != "source_observation" || e[0].Status != "OBSERVED" || e[0].Output == "" {
		t.Fatalf("invalid source evidence: %+v", e)
	}
}

func TestGeneratedSetupFailureNotReproduced(t *testing.T) {
	for _, output := range []string{"FAIL project/pkg [build failed]", "FAIL project/pkg [setup failed]", "SyntaxError: invalid syntax", "ImportError: missing", "Error: Cannot find module './x'"} {
		t.Run(output, func(t *testing.T) {
			h := fixture(t)
			count := 0
			h.execute = func(_ context.Context, _ string, _ []string, w io.Writer) execution {
				count++
				if count == 1 {
					writeGoEvents(w, "pass")
					return execution{ExitCode: 0}
				}
				fmt.Fprint(w, output)
				return execution{ExitCode: 1}
			}
			call(t, h, "create_test", map[string]any{"path": "pkg/new_test.go", "content": generatedSource})
			call(t, h, "run_generated_test", map[string]any{"test_id": "generated-test-1"})
			if h.Evidence()[0].Status != "UNVERIFIED" {
				t.Fatal("invalid test reported as reproduced")
			}
		})
	}
}

func TestArtifactFailureCannotClaimPass(t *testing.T) {
	h := fixture(t)
	h.opts.ArtifactDir = filepath.Join(t.TempDir(), "missing", "path")
	h.execute = func(_ context.Context, _ string, _ []string, w io.Writer) execution {
		fmt.Fprint(w, "ok")
		return execution{ExitCode: 0}
	}
	if c := h.Run(context.Background(), "test"); c.Status != "ERROR" {
		t.Fatalf("artifact error hidden: %+v", c)
	}
}

func TestDockerIntegration(t *testing.T) {
	image := os.Getenv("SWIFTPROOF_TEST_DOCKER_IMAGE")
	if image == "" {
		t.Skip("set SWIFTPROOF_TEST_DOCKER_IMAGE to an already-present Linux image with /bin/sh and cp")
	}
	h := fixture(t)
	h.opts.Image = image
	t.Setenv("SWIFTPROOF_HOST_SECRET", "must-not-reach-container")
	h.opts.Commands["test"] = []string{"/bin/sh", "-c", `test -f /workspace/pkg/main.go && test -z "$SWIFTPROOF_HOST_SECRET" && ! touch /source/mutated && touch /workspace/disposable && echo isolated`}
	c := h.Run(context.Background(), "test")
	if c.Status != "PASS" || !strings.Contains(c.Output, "isolated") {
		t.Fatalf("sandbox check failed: %+v", c)
	}
	if _, err := os.Stat(filepath.Join(h.candidate, "disposable")); !os.IsNotExist(err) {
		t.Error("container write reached host snapshot")
	}
}
