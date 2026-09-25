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

	"github.com/gvinsot/SwiftProof/app/internal/coverage"
	"github.com/gvinsot/SwiftProof/app/internal/model"
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

// --- Changed-line execution measurement --------------------------------------
//
// The coverage path adds a second container channel to an otherwise unchanged
// sandbox. These tests pin the two properties that keep it honest: the boundary
// is exactly the boundary dockerArgs already had, and no absent, truncated or
// unretainable profile can become a not-executed claim.

// coverageFrame builds the length-declared frame the sandbox wrapper emits on
// the payload channel, from the same constants the decoder uses.
func coverageFrame(body string) string {
	return fmt.Sprintf("%s%d\n%s%s", coverage.FrameHeader, len(body), body, coverage.FrameFooter)
}

// goCoverageCommand is a realistic configured coverage argv: the placeholder is
// expanded by the harness, never by the caller.
func goCoverageCommand() []string {
	return []string{"go", "test", "-covermode=count", "-coverprofile=" + coverage.Placeholder, "./..."}
}

func artifactByKind(h *Harness, kind string) (model.Artifact, bool) {
	for _, a := range h.Artifacts() {
		if a.Kind == kind {
			return a, true
		}
	}
	return model.Artifact{}, false
}

func indexOfArg(args []string, want string) int {
	for i, a := range args {
		if a == want {
			return i
		}
	}
	return -1
}

func TestCoverageArgsKeepIsolationAndArgvVerbatim(t *testing.T) {
	h := fixture(t)
	command := append(goCoverageCommand(), "; touch /source/pwned", `$(echo attack)`)
	plain := h.dockerArgs("name", h.candidate, command)
	args := h.dockerArgsCoverage("name", h.candidate, command)
	for _, required := range []string{"--rm", "--pull=never", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--pids-limit=128", "--user=65534:65534", "--memory=1024m", "--memory-swap=1024m", "--cpus=2", "--env=GOPROXY=off", "--workdir=/workspace", "type=bind,src=" + h.candidate + ",dst=/source,readonly"} {
		if !contains(args, required) {
			t.Errorf("coverage run drops isolation option %s", required)
		}
	}
	for _, required := range []string{"/workspace:rw,exec,nosuid,nodev,mode=1777,size=1024m", "/tmp:rw,exec,nosuid,nodev,mode=1777,size=1024m"} {
		if !contains(args, required) {
			t.Errorf("coverage tmpfs differs from the plain run: missing %s", required)
		}
	}
	for i, arg := range args {
		if arg == "--network" && args[i+1] != "none" {
			t.Error("network enabled by default on the coverage run")
		}
	}
	// A configured command may legitimately contain any token, so only the
	// options the harness itself adds are scanned for forbidden arguments.
	flags, plainFlags := args[:len(args)-len(command)], plain[:len(plain)-len(command)]
	for _, forbidden := range []string{"--privileged", "--env-file", "-v", "--volume", "-i", "-t", "-it", "--interactive", "--tty"} {
		if contains(flags, forbidden) {
			t.Errorf("coverage run adds %s: the sandbox keeps no writable host path, and the payload channel needs stdout and stderr on separate host descriptors, which a TTY merges", forbidden)
		}
	}
	mounts, envs, plainEnvs := 0, 0, 0
	for _, a := range flags {
		if a == "--mount" {
			mounts++
		}
		if strings.HasPrefix(a, "--env") {
			envs++
		}
	}
	for _, a := range plainFlags {
		if strings.HasPrefix(a, "--env") {
			plainEnvs++
		}
	}
	if mounts != 1 {
		t.Errorf("coverage run declares %d mounts; the read-only source bind must remain the only one", mounts)
	}
	if envs != plainEnvs {
		t.Errorf("coverage run passes %d environment options against %d for a plain run", envs, plainEnvs)
	}
	// Compared position by position rather than flag by flag, so an option added
	// to both builders keeps this test passing while an option added to only one
	// fails it.
	if len(args) != len(plain) {
		t.Fatalf("coverage argv has %d arguments against %d for a plain run", len(args), len(plain))
	}
	differing := []int{}
	for i := range args {
		if args[i] != plain[i] {
			differing = append(differing, i)
		}
	}
	if len(differing) != 1 {
		t.Fatalf("coverage argv differs from the plain argv at positions %v; only the wrapper script may differ", differing)
	}
	if plain[differing[0]] != wrapperScript || args[differing[0]] != coverageScript {
		t.Fatalf("the differing argument is not the wrapper script: %q against %q", plain[differing[0]], args[differing[0]])
	}
	if !reflect.DeepEqual(args[len(args)-len(command):], command) {
		t.Fatal("coverage command arguments reinterpreted")
	}
}

func TestNonCoverageKindsKeepExecWrapper(t *testing.T) {
	h := fixture(t)
	command := []string{"go", "test", "./..."}
	plain := h.dockerArgs("name", h.candidate, command)
	args := h.dockerArgsCoverage("name", h.candidate, command)
	at := indexOfArg(plain, "--entrypoint=/bin/sh")
	if at < 0 || at+4 >= len(plain) {
		t.Fatalf("shell entrypoint form changed: %v", plain)
	}
	if plain[at+1] != h.opts.Image || plain[at+2] != "-c" || plain[at+4] != "swiftproof" {
		t.Fatalf("shell invocation form changed: %v", plain[at:at+5])
	}
	if plain[at+3] != `cp -R /source/. /workspace/ && exec "$@"` {
		t.Fatalf("non-coverage kinds no longer use the fixed argument-preserving entrypoint: %q", plain[at+3])
	}
	if indexOfArg(args, "--entrypoint=/bin/sh") != at {
		t.Fatalf("coverage run places the shell entrypoint elsewhere: %v", args)
	}
	if args[at+3] != coverageScript || args[at+3] == plain[at+3] {
		t.Fatalf("the coverage run must differ from a plain run only by carrying the coverage script: %q", args[at+3])
	}
	// The frame producer is built from the decoder's own constants, and it still
	// copies the read-only source into the ephemeral workspace and nothing else.
	for _, want := range []string{coverage.FrameHeader, strings.TrimSuffix(coverage.FrameFooter, "\n"), coverage.ProfilePath, "cp -R /source/. /workspace/"} {
		if !strings.Contains(coverageScript, want) {
			t.Errorf("coverage script does not contain %q", want)
		}
	}
}

func TestCoverageProfileIsCapturedAndRetained(t *testing.T) {
	const goProfile = "mode: count\nexample.com/m/pkg/main.go:1.13,3.2 2 1\nexample.com/m/pkg/main.go:5.2,6.9 1 0\n"
	cases := []struct {
		name, body string
	}{
		{"go_profile", goProfile},
		// A Go import path may contain a colon, and that is the one profile
		// shape display redaction would rewrite. The frame stays well formed, so
		// byte equality here proves the payload channel is returned raw: a
		// redacted copy would differ, and would no longer parse at all.
		{"redaction_sensitive_profile", goProfile + "example.com/m/internal/api_key:v2/store.go:5.2,6.9 1 0\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := fixture(t)
			h.opts.Commands[coverage.CommandKey] = goCoverageCommand()
			h.executeCapture = func(_ context.Context, _ string, _ []string, log, payload io.Writer) execution {
				fmt.Fprint(log, "ok  example.com/m/pkg\tapi_key=SECRETVALUE\n")
				fmt.Fprint(payload, coverageFrame(tc.body))
				return execution{ExitCode: 0}
			}
			c, profile, sha, reason := h.RunCoverage(context.Background())
			if reason != "" {
				t.Fatalf("a well-formed frame was not measured: %s", reason)
			}
			if c.Status != "PASS" {
				t.Fatalf("recorded check status %s", c.Status)
			}
			if string(profile) != tc.body {
				t.Fatalf("the payload channel was transformed before it could be parsed and hashed: %q", profile)
			}
			if tc.name == "redaction_sensitive_profile" && Redact(tc.body) == tc.body {
				t.Fatal("this case can no longer distinguish a raw payload from a redacted one")
			}
			// The log channel is the displayed one: it is redacted, and it never
			// carries the payload.
			if strings.Contains(c.Output, "SECRETVALUE") || !strings.Contains(c.Output, "[REDACTED]") {
				t.Fatalf("coverage log output is not redacted: %q", c.Output)
			}
			for _, leak := range []string{coverage.FrameHeader, strings.TrimSuffix(coverage.FrameFooter, "\n"), "mode: count"} {
				if strings.Contains(c.Output, leak) {
					t.Errorf("the payload frame leaked into the check log: %q", leak)
				}
			}
			a, ok := artifactByKind(h, "coverage_profile")
			if !ok {
				t.Fatal("measured coverage retained no profile artifact")
			}
			b, err := os.ReadFile(a.Path)
			if err != nil {
				t.Fatal(err)
			}
			if string(b) != tc.body {
				t.Fatalf("retained artifact is not the profile that was measured: %q", b)
			}
			sum := sha256.Sum256(b)
			if hex.EncodeToString(sum[:]) != sha || a.SHA256 != sha {
				t.Fatalf("reported profile hash %s does not match the retained bytes %s", sha, hex.EncodeToString(sum[:]))
			}
			found := false
			for _, e := range h.Audit() {
				if e.Tool == "run_"+coverage.CommandKey {
					found = true
					if e.Status != c.Status {
						t.Errorf("audit records status %s for a %s check", e.Status, c.Status)
					}
				}
			}
			if !found {
				t.Fatal("the coverage run is absent from the audit trail")
			}
		})
	}
}

func TestCoveragePlaceholderExpansion(t *testing.T) {
	h := fixture(t)
	h.opts.Commands[coverage.CommandKey] = goCoverageCommand()
	want := []string{"go", "test", "-covermode=count", "-coverprofile=" + coverage.ProfilePath, "./..."}
	var got []string
	h.executeCapture = func(_ context.Context, _ string, args []string, _, payload io.Writer) execution {
		got = append([]string(nil), args[len(args)-len(want):]...)
		fmt.Fprint(payload, coverageFrame("mode: set\nexample.com/m/pkg/main.go:1.1,2.2 1 1\n"))
		return execution{ExitCode: 0}
	}
	c, _, _, reason := h.RunCoverage(context.Background())
	if reason != "" {
		t.Fatalf("expanded coverage command was not measured: %s", reason)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("container received %v; the placeholder must be replaced by the fixed in-container profile path", got)
	}
	if !reflect.DeepEqual(c.Command, want) {
		t.Fatalf("recorded command %v does not show the argv that ran", c.Command)
	}
	if !contains(h.opts.Commands[coverage.CommandKey], "-coverprofile="+coverage.Placeholder) {
		t.Error("expansion mutated the trusted policy command")
	}
	for _, arg := range append(append([]string(nil), got...), c.Command...) {
		if strings.Contains(arg, coverage.Placeholder) {
			t.Errorf("unexpanded placeholder survived in %q", arg)
		}
	}
}

func TestTruncatedCoveragePayloadYieldsNoProfile(t *testing.T) {
	cases := []struct {
		name  string
		frame func(limit int) string
	}{
		// More bytes than the payload budget allows: the writer reports the cut
		// and the frame can no longer be trusted, however well formed it looks.
		{"payload_exceeds_budget", func(limit int) string {
			row := "example.com/m/pkg/wide.go:1.1,2.2 1 1\n"
			return coverageFrame("mode: count\n" + strings.Repeat(row, limit/len(row)+2))
		}},
		// The declared length is the only authority on where the profile ends: a
		// body shorter than declared must fail rather than parse as a shorter
		// profile, because a shorter profile reads as "these lines never ran".
		{"declared_length_exceeds_body", func(int) string {
			body := "mode: count\nexample.com/m/pkg/main.go:1.1,2.2 1 1\n"
			return fmt.Sprintf("%s%d\n%s%s", coverage.FrameHeader, len(body)+4096, body, coverage.FrameFooter)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := fixture(t)
			h.opts.MaxOutputBytes = 256
			h.opts.Commands[coverage.CommandKey] = goCoverageCommand()
			h.executeCapture = func(_ context.Context, _ string, _ []string, _, payload io.Writer) execution {
				fmt.Fprint(payload, tc.frame(PayloadLimit(h.opts.MaxOutputBytes)))
				return execution{ExitCode: 0}
			}
			c, profile, sha, reason := h.RunCoverage(context.Background())
			if profile != nil || sha != "" {
				t.Fatalf("a cut-short payload produced a profile of %d bytes", len(profile))
			}
			if reason != coverage.ErrTruncated.Error() {
				t.Fatalf("truncated payload reported as %q", reason)
			}
			if _, ok := artifactByKind(h, "coverage_profile"); ok {
				t.Fatal("a rejected payload was retained as a coverage profile")
			}
			a, ok := artifactByKind(h, "coverage_payload_rejected")
			if !ok {
				t.Fatal("the rejected payload was discarded; the not-measured verdict is no longer auditable")
			}
			b, err := os.ReadFile(a.Path)
			if err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(b)
			if len(b) == 0 || a.SHA256 != hex.EncodeToString(sum[:]) {
				t.Fatalf("rejected payload artifact does not match its recorded hash: %d bytes", len(b))
			}
			if c.Status != "PASS" {
				t.Errorf("the command itself passed but the check reports %s", c.Status)
			}
		})
	}
}

// A coverage command that writes no profile is the ordinary failure mode, and
// it must reach the caller as a reason. Absent data is the one input that could
// otherwise render as "every added line never ran".
func TestAbsentCoveragePayloadYieldsNoProfile(t *testing.T) {
	h := fixture(t)
	h.opts.Commands[coverage.CommandKey] = goCoverageCommand()
	h.executeCapture = func(_ context.Context, _ string, _ []string, log, _ io.Writer) execution {
		fmt.Fprint(log, "no test files\n")
		return execution{ExitCode: 0}
	}
	c, profile, sha, reason := h.RunCoverage(context.Background())
	if profile != nil || sha != "" {
		t.Fatalf("absent coverage data produced %d profile bytes", len(profile))
	}
	if reason != coverage.ErrNoProfile.Error() {
		t.Fatalf("absent coverage data reported as %q", reason)
	}
	if c.Status != "PASS" {
		t.Errorf("the command itself passed but the check reports %s", c.Status)
	}
	if _, ok := artifactByKind(h, "coverage_profile"); ok {
		t.Fatal("a profile artifact exists although no profile arrived")
	}
}

// A frame can be well formed and still carry something other than a profile.
// The harness validates before labelling, so such a payload yields a reason and
// never a measurement, and nothing is filed as a coverage profile.
func TestNonProfilePayloadYieldsNoProfile(t *testing.T) {
	cases := []struct {
		name, body, reason string
	}{
		{"not_a_go_profile", "PASS\nok  example.com/m/pkg\t0.01s\n", coverage.ErrNotGo.Error()},
		{"malformed_row", "mode: count\nexample.com/m/pkg/main.go:1.13,3.2 2 1\nnot a block row\n", "the coverage profile could not be parsed at line 3"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := fixture(t)
			h.opts.Commands[coverage.CommandKey] = goCoverageCommand()
			h.executeCapture = func(_ context.Context, _ string, _ []string, _, payload io.Writer) execution {
				fmt.Fprint(payload, coverageFrame(tc.body))
				return execution{ExitCode: 0}
			}
			_, profile, sha, reason := h.RunCoverage(context.Background())
			if profile != nil || sha != "" {
				t.Fatalf("a payload that is not a coverage profile produced %d profile bytes", len(profile))
			}
			if reason != tc.reason {
				t.Fatalf("reason is %q, want %q", reason, tc.reason)
			}
			if _, ok := artifactByKind(h, "coverage_profile"); ok {
				t.Fatal("a payload that is not a coverage profile was filed as one")
			}
			if _, ok := artifactByKind(h, "coverage_payload_rejected"); !ok {
				t.Fatal("the rejected payload was discarded; the not-measured verdict is no longer auditable")
			}
		})
	}
}

func TestCoverageArtifactFailureDiscardsProfile(t *testing.T) {
	h := fixture(t)
	h.opts.Commands[coverage.CommandKey] = goCoverageCommand()
	// saveArtifact writes <ArtifactDir>/<runID>-<checkID>-coverage.out with
	// O_EXCL, so an occupied path is an unavoidable retention failure.
	blocked := filepath.Join(h.opts.ArtifactDir, h.runID+"-check-1-coverage.out")
	if err := os.WriteFile(blocked, []byte("occupied"), 0600); err != nil {
		t.Fatal(err)
	}
	h.executeCapture = func(_ context.Context, _ string, _ []string, _, payload io.Writer) execution {
		fmt.Fprint(payload, coverageFrame("mode: count\nexample.com/m/pkg/main.go:1.1,2.2 1 0\n"))
		return execution{ExitCode: 0}
	}
	c, profile, sha, reason := h.RunCoverage(context.Background())
	if c.ID != "check-1" {
		t.Fatalf("artifact path assumption broken: the first check is %s", c.ID)
	}
	if profile != nil || sha != "" {
		t.Fatalf("a coverage claim survived with no recorded evidence: %d profile bytes, hash %q", len(profile), sha)
	}
	if reason != coverage.ErrArtifact.Error() {
		t.Fatalf("unretainable profile reported as %q", reason)
	}
	if _, ok := artifactByKind(h, "coverage_profile"); ok {
		t.Fatal("a profile that could not be written is listed as an artifact")
	}
	b, err := os.ReadFile(blocked)
	if err != nil || string(b) != "occupied" {
		t.Fatalf("the harness overwrote an existing artifact: %q %v", b, err)
	}
}

// Redact runs over every displayed string, and the retained artifact is the raw
// profile the container emitted. A profile whose paths read like credential
// names must survive byte identical, or the hash recorded in the report would
// no longer match the bytes the parser saw.
func TestGoProfileSurvivesRedaction(t *testing.T) {
	profile := strings.Join([]string{
		"mode: count",
		"example.com/m/internal/secret/store.go:12.31,14.2 1 1",
		"example.com/m/internal/auth/password.go:8.20,9.15 2 0",
		"example.com/m/internal/auth/auth_token.go:3.1,5.4 1 7",
		"example.com/m/internal/client/api_key.go:21.9,23.3 2 0",
		"example.com/m/internal/client/client_secret.go:1.1,2.2 1 1",
		"",
	}, "\n")
	redacted := Redact(profile)
	if redacted != profile {
		t.Fatalf("redaction mangled a well-formed coverage profile:\n%s", redacted)
	}
	p, err := coverage.ParseGoProfile([]byte(redacted))
	if err != nil {
		t.Fatalf("a redacted profile no longer parses: %v", err)
	}
	if len(p.Blocks) != 5 {
		t.Fatalf("redaction removed instrumented blocks: %d of 5 remain", len(p.Blocks))
	}
}

func TestCoverageLimitDerivation(t *testing.T) {
	const floor, ceiling = 256 * 1024, 4 * 1024 * 1024
	cases := []struct {
		name            string
		maxOutput, want int
	}{
		{"smallest_policy_floors", 256, floor},
		{"below_floor", 8 * 1024, floor},
		{"exactly_floor", 16 * 1024, floor},
		{"sixteen_times", 64 * 1024, 16 * 64 * 1024},
		{"default_policy", 65536, 16 * 65536},
		{"exactly_ceiling", 256 * 1024, ceiling},
		{"above_ceiling", 1024 * 1024, ceiling},
		{"largest_policy_caps", 4 * 1024 * 1024, ceiling},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := PayloadLimit(tc.maxOutput)
			if got != tc.want {
				t.Fatalf("coverage budget for max_output_bytes=%d is %d, want %d", tc.maxOutput, got, tc.want)
			}
			if got < tc.maxOutput {
				t.Fatalf("the coverage budget %d is below the log budget %d it derives from", got, tc.maxOutput)
			}
		})
	}
}
