package harness

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/gvinsot/SwiftProof/internal/coverage"
)

// This test uses a real, preloaded Go image. No dependency downloads are needed.
// It verifies actual compiler execution, test attribution, isolation, and artifacts.
func TestDockerGoDifferentialIntegration(t *testing.T) {
	image := os.Getenv("SWIFTPROOF_TEST_DOCKER_IMAGE")
	if image == "" {
		t.Skip("set SWIFTPROOF_TEST_DOCKER_IMAGE to a preloaded golang Linux image")
	}
	t.Setenv("SWIFTPROOF_HOST_SECRET", "must-not-reach-container")
	for _, scenario := range []struct{ name, candidate, want string }{
		{"real_regression", "package sample\nfunc Clamp(n int) int { return n }\n", "REPRODUCED"},
		{"unrelated_suite_failure", "package sample\nfunc Clamp(n int) int { if n < 0 { return 0 }; return n }\n", "NOT_REPRODUCED"},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			base, head, artifacts := t.TempDir(), t.TempDir(), t.TempDir()
			original := map[string]string{"go.mod": "module example.test/sample\n\ngo 1.23.0\n", "value.go": "package sample\nfunc Clamp(n int) int { if n < 0 { return 0 }; return n }\n", ".env": "SECRET=must-not-enter-sandbox\n"}
			for _, dir := range []string{base, head} {
				for path, content := range original {
					if err := os.WriteFile(filepath.Join(dir, path), []byte(content), 0644); err != nil {
						t.Fatal(err)
					}
				}
			}
			if err := os.WriteFile(filepath.Join(head, "value.go"), []byte(scenario.candidate), 0644); err != nil {
				t.Fatal(err)
			}
			// An existing candidate-only test always fails. Selecting only the generated
			// test must prevent this unrelated failure from masquerading as a reproducer.
			existing := `package sample
import "testing"
func TestUnrelatedExistingFailure(t *testing.T) { t.Fatal("unrelated existing failure must not count") }
`
			if err := os.WriteFile(filepath.Join(head, "existing_test.go"), []byte(existing), 0644); err != nil {
				t.Fatal(err)
			}
			h, err := New(Options{BaseDir: base, CandidateDir: head, ArtifactDir: artifacts, Image: image, Timeout: 2 * time.Minute, MaxRuntime: 5 * time.Minute, MaxGeneratedTests: 1, Commands: map[string][]string{"generated_test": {"go", "test", "{package}"}}})
			if err != nil {
				t.Fatal(err)
			}
			defer h.Close()
			generated := `package sample
import (
 "net"
 "os"
 "testing"
 "time"
)
func TestSwiftProofClampAndSandbox(t *testing.T) {
 if os.Geteuid() == 0 { t.Fatal("sandbox must be non-root") }
 if os.Getenv("SWIFTPROOF_HOST_SECRET") != "" { t.Fatal("host secret reached sandbox") }
 if _, err := os.Stat("/source/.env"); !os.IsNotExist(err) { t.Fatal("secret file reached sandbox") }
 if err := os.WriteFile("/source/host-write", []byte("unsafe"), 0644); err == nil { t.Fatal("source mount is writable") }
 if err := os.WriteFile("/etc/swiftproof-write", []byte("unsafe"), 0644); err == nil { t.Fatal("root filesystem is writable") }
 if err := os.WriteFile("/workspace/container-only", []byte("ephemeral"), 0644); err != nil { t.Fatal(err) }
 interfaces, err := net.Interfaces(); if err != nil { t.Fatal(err) }
 for _, iface := range interfaces { if iface.Flags & net.FlagLoopback == 0 { t.Fatalf("unexpected network interface: %s", iface.Name) } }
 connection, err := net.DialTimeout("tcp", "192.0.2.1:443", 200*time.Millisecond)
 if err == nil { connection.Close(); t.Fatal("sandbox connected to external network") }
 if got := Clamp(-1); got != 0 { t.Fatalf("Clamp(-1) = %d; want 0", got) }
}
`
			call(t, h, "create_test", map[string]any{"path": "swiftproof_regression_test.go", "content": generated, "description": "Negative inputs must clamp to zero"})
			out := call(t, h, "run_generated_test", map[string]any{"test_id": "generated-test-1"})
			evidence := h.Evidence()
			if len(evidence) != 1 || evidence[0].Status != scenario.want {
				t.Fatalf("real Docker differential outcome is wrong: %s", out)
			}
			if evidence[0].Runner != "go_test_json" || len(evidence[0].TestNames) != 1 {
				t.Fatalf("missing named-test provenance: %+v", evidence)
			}
			checks := h.Checks()
			if len(checks) != 2 || checks[0].Status != "PASS" {
				t.Fatalf("baseline did not execute: %+v", checks)
			}
			for _, check := range checks {
				if strings.Contains(check.Output, "unrelated existing failure must not count") {
					t.Fatal("unrelated test executed")
				}
			}
			for _, dir := range []string{base, head, h.base, h.candidate} {
				for _, path := range []string{"host-write", "container-only", "swiftproof_regression_test.go"} {
					if _, err := os.Stat(filepath.Join(dir, path)); !os.IsNotExist(err) {
						t.Fatalf("sandbox modified host snapshot: %s", filepath.Join(dir, path))
					}
				}
			}
			for _, entry := range []struct{ dir, want string }{{base, original["value.go"]}, {head, scenario.candidate}} {
				b, err := os.ReadFile(filepath.Join(entry.dir, "value.go"))
				if err != nil || string(b) != entry.want {
					t.Fatal("original source changed")
				}
			}
			found := false
			for _, artifact := range h.Artifacts() {
				b, err := os.ReadFile(artifact.Path)
				if err != nil {
					t.Fatal(err)
				}
				sum := sha256.Sum256(b)
				if hex.EncodeToString(sum[:]) != artifact.SHA256 {
					t.Fatal("artifact hash mismatch")
				}
				if artifact.Kind == "generated_test" {
					found = true
					if string(b) != generated {
						t.Fatal("retained test does not match executed source")
					}
				}
			}
			if (scenario.want == "REPRODUCED") != found {
				t.Fatal("incorrect reproducer retention")
			}
			if err := h.Close(); err != nil {
				t.Fatal(err)
			}
			for _, artifact := range h.Artifacts() {
				if _, err := os.Stat(artifact.Path); err != nil {
					t.Fatal("Close removed evidence artifacts")
				}
			}
			if c := h.Run(context.Background(), "test"); c.Status != "ERROR" {
				t.Fatal("closed harness accepted execution")
			}
		})
	}
}

// dockerCoverageFixture builds a real snapshot whose trusted policy configures
// only the coverage command, and returns the harness together with the
// untouched host source directory. The snapshot carries a secret-bearing file
// so every coverage run also re-proves that snapshotting excluded it.
func dockerCoverageFixture(t *testing.T, image string, command []string) (*Harness, string) {
	t.Helper()
	source := t.TempDir()
	for path, content := range map[string]string{
		"go.mod":   "module example.test/sample\n\ngo 1.23.0\n",
		"value.go": "package sample\n\nfunc Clamp(n int) int {\n\tif n < 0 {\n\t\treturn 0\n\t}\n\treturn n\n}\n",
		".env":     "SECRET=must-not-enter-sandbox\n",
	} {
		if err := os.WriteFile(filepath.Join(source, path), []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}
	h, err := New(Options{CandidateDir: source, ArtifactDir: t.TempDir(), Image: image, Timeout: 2 * time.Minute, MaxRuntime: 5 * time.Minute, Commands: map[string][]string{coverage.CommandKey: command}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.Close() })
	return h, source
}

// The coverage wrapper is a second entry into the sandbox, so it is held to the
// identical boundary: the container asserts its own confinement from the
// inside, and the host asserts afterwards that nothing escaped. Coverage may
// add signals; it may never buy them with a weaker sandbox.
func TestDockerCoverageBoundaryUnchanged(t *testing.T) {
	image := os.Getenv("SWIFTPROOF_TEST_DOCKER_IMAGE")
	if image == "" {
		t.Skip("set SWIFTPROOF_TEST_DOCKER_IMAGE to a preloaded golang Linux image")
	}
	t.Setenv("SWIFTPROOF_HOST_SECRET", "must-not-reach-container")
	// Every violation exits non-zero with its own sentence, so a failure names
	// the boundary that broke instead of only an exit code. The command also
	// writes a valid profile, so the boundary is asserted on a coverage run that
	// otherwise succeeds end to end rather than on a degenerate one.
	boundary := `fail() { echo "BOUNDARY VIOLATION: $1"; exit 1; }
[ "$(id -u)" -ne 0 ] || fail "coverage container runs as root"
touch /swiftproof-root-write 2>/dev/null && fail "root filesystem is writable"
touch /source/swiftproof-host-write 2>/dev/null && fail "read-only source mount is writable"
touch /workspace/swiftproof-container-only || fail "ephemeral workspace is not writable"
[ -z "$SWIFTPROOF_HOST_SECRET" ] || fail "host environment secret reached the coverage container"
[ ! -e /source/.env ] && [ ! -e /workspace/.env ] || fail "secret file reached the coverage container"
printf 'mode: set\nexample.test/sample/value.go:3.23,4.11 1 1\n' > ` + coverage.Placeholder + `
echo "boundary intact"`
	h, source := dockerCoverageFixture(t, image, []string{"/bin/sh", "-c", boundary})
	listing := func(dir string) string {
		var names []string
		if err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(dir, path)
			if err != nil {
				return err
			}
			names = append(names, filepath.ToSlash(rel))
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		sort.Strings(names)
		return strings.Join(names, " ")
	}
	before := map[string]string{source: listing(source), h.candidate: listing(h.candidate)}
	// The argv actually handed to Docker is recorded, so the boundary is checked
	// on what ran and not only on what the argument builder returns.
	var containerName string
	var executed []string
	capture := h.executeCapture
	h.executeCapture = func(ctx context.Context, name string, args []string, log, payload io.Writer) execution {
		containerName, executed = name, append([]string(nil), args...)
		return capture(ctx, name, args, log, payload)
	}
	c, _, _, reason := h.RunCoverage(context.Background())
	if c.Status != "PASS" || reason != "" {
		t.Fatalf("coverage sandbox boundary check did not pass: status=%s reason=%s output=%s", c.Status, reason, c.Output)
	}
	if !strings.Contains(c.Output, "boundary intact") {
		t.Fatalf("coverage command did not report its in-container assertions: %s", c.Output)
	}
	present := map[string]bool{}
	for _, arg := range executed {
		present[arg] = true
	}
	for _, required := range []string{"--rm", "--read-only", "--pull=never", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--user=65534:65534", "--network", "none", "type=bind,src=" + h.candidate + ",dst=/source,readonly"} {
		if !present[required] {
			t.Errorf("coverage run dropped isolation option %s: %v", required, executed)
		}
	}
	for i, arg := range executed {
		switch {
		case arg == "-v" || arg == "--volume" || strings.HasPrefix(arg, "-v=") || strings.HasPrefix(arg, "--volume="):
			t.Errorf("coverage run created a volume: %v", executed)
		case arg == "--privileged" || arg == "--env-file" || strings.HasPrefix(arg, "--cap-add"):
			t.Errorf("coverage run weakened the sandbox with %s", arg)
		case arg == "--mount" && i+1 < len(executed):
			if mount := executed[i+1]; !strings.HasSuffix(mount, ",readonly") || !strings.Contains(mount, "dst=/source") {
				t.Errorf("coverage run mounted a writable host path: %s", mount)
			}
		}
	}
	for dir, want := range before {
		if got := listing(dir); got != want {
			t.Fatalf("coverage run changed host snapshot %s: %s", dir, got)
		}
	}
	// --rm plus the harness's own bounded cleanup must leave nothing behind: a
	// surviving container is a surviving writable boundary.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "docker", "ps", "-a", "--filter", "name="+containerName, "--format", "{{.Names}}").Output()
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(out)) != "" {
		t.Fatalf("coverage container survived the run: %s", out)
	}
}

// The payload channel is a length-declared frame, not a convention. The bytes
// the container wrote must arrive byte for byte and the retained artifact must
// hash to exactly what the caller was handed: a coverage verdict with no
// recorded, hashed evidence is unfalsifiable.
func TestDockerCoverageFrameRoundTrip(t *testing.T) {
	image := os.Getenv("SWIFTPROOF_TEST_DOCKER_IMAGE")
	if image == "" {
		t.Skip("set SWIFTPROOF_TEST_DOCKER_IMAGE to a preloaded golang Linux image")
	}
	// The container command is generated from the expected bytes, so the
	// assertion cannot be quietly written around whatever the wrapper emits.
	want := "mode: count\nexample.test/sample/value.go:3.23,5.4 1 7\nexample.test/sample/value.go:5.4,7.3 1 0\n"
	script := "printf '" + strings.ReplaceAll(want, "\n", `\n`) + "' > " + coverage.Placeholder
	h, _ := dockerCoverageFixture(t, image, []string{"/bin/sh", "-c", script})
	c, profile, sha, reason := h.RunCoverage(context.Background())
	if reason != "" {
		t.Fatalf("a profile the container did emit was reported as not measured: %s (output %s)", reason, c.Output)
	}
	if c.Status != "PASS" {
		t.Fatalf("coverage command did not run: %+v", c)
	}
	if string(profile) != want {
		t.Fatalf("frame transport changed the profile bytes: %q", string(profile))
	}
	if strings.Contains(string(profile), coverage.FrameHeader) || strings.Contains(string(profile), strings.TrimSuffix(coverage.FrameFooter, "\n")) {
		t.Fatalf("frame markers leaked into the profile: %q", string(profile))
	}
	if _, err := coverage.ParseGoProfile(profile); err != nil {
		t.Fatalf("round-tripped profile does not parse: %v", err)
	}
	sum := sha256.Sum256([]byte(want))
	if sha != hex.EncodeToString(sum[:]) {
		t.Fatalf("reported digest does not cover the bytes the container wrote: %s", sha)
	}
	retained := 0
	for _, artifact := range h.Artifacts() {
		if artifact.Kind != "coverage_profile" {
			continue
		}
		retained++
		b, err := os.ReadFile(artifact.Path)
		if err != nil {
			t.Fatal(err)
		}
		if string(b) != want {
			t.Fatalf("retained coverage artifact does not match the measured profile: %q", string(b))
		}
		digest := sha256.Sum256(b)
		if hex.EncodeToString(digest[:]) != artifact.SHA256 || artifact.SHA256 != sha {
			t.Fatalf("retained coverage artifact hash mismatch: artifact %s, reported %s", artifact.SHA256, sha)
		}
	}
	if retained != 1 {
		t.Fatalf("expected exactly one retained coverage_profile artifact, got %d", retained)
	}
}

// The whole transport rests on one property: the command's own output can never
// reach the payload channel. Noise on either of the command's descriptors must
// land in the recorded log, and a command that forges a frame on its standard
// output must not be able to substitute a profile.
func TestDockerCoverageSeparatesLogFromPayload(t *testing.T) {
	image := os.Getenv("SWIFTPROOF_TEST_DOCKER_IMAGE")
	if image == "" {
		t.Skip("set SWIFTPROOF_TEST_DOCKER_IMAGE to a preloaded golang Linux image")
	}
	want := "mode: count\nexample.test/sample/value.go:3.23,5.4 1 4\n"
	script := strings.Join([]string{
		`echo "noise-on-stdout"`,
		`echo "noise-on-stderr" >&2`,
		`echo "` + coverage.FrameHeader + `5"`,
		`echo "FORGED-PAYLOAD"`,
		`echo "` + strings.TrimSuffix(coverage.FrameFooter, "\n") + `"`,
		"printf '" + strings.ReplaceAll(want, "\n", `\n`) + "' > " + coverage.Placeholder,
		`echo "trailing-noise-on-stdout"`,
	}, "; ")
	h, _ := dockerCoverageFixture(t, image, []string{"/bin/sh", "-c", script})
	c, profile, _, reason := h.RunCoverage(context.Background())
	if reason != "" {
		t.Fatalf("command output reaching the payload channel destroyed the measurement: %s (output %s)", reason, c.Output)
	}
	if c.Status != "PASS" {
		t.Fatalf("coverage command did not run: %+v", c)
	}
	for _, noise := range []string{"noise-on-stdout", "noise-on-stderr", "trailing-noise-on-stdout", "FORGED-PAYLOAD"} {
		if !strings.Contains(c.Output, noise) {
			t.Errorf("command output %q was lost instead of recorded in the check log: %s", noise, c.Output)
		}
		if strings.Contains(string(profile), noise) {
			t.Fatalf("command output %q reached the coverage payload: %q", noise, string(profile))
		}
	}
	if string(profile) != want {
		t.Fatalf("the profile is not the bytes the command wrote: %q", string(profile))
	}
	parsed, err := coverage.ParseGoProfile(profile)
	if err != nil {
		t.Fatalf("profile carried alongside command output does not decode cleanly: %v", err)
	}
	if parsed.Mode != "count" || len(parsed.Blocks) != 1 || parsed.Blocks[0].Count != 4 {
		t.Fatalf("decoded profile does not describe the recorded run: %+v", parsed)
	}
	// The retained evidence must show the same separation as the returned bytes.
	for _, artifact := range h.Artifacts() {
		b, err := os.ReadFile(artifact.Path)
		if err != nil {
			t.Fatal(err)
		}
		if artifact.Kind == "coverage_profile" && strings.Contains(string(b), "noise-on") {
			t.Fatalf("retained coverage profile contains command output: %q", string(b))
		}
		if artifact.Kind == "check_output" && !strings.Contains(string(b), "noise-on-stderr") {
			t.Fatalf("retained check log lost the command output: %q", string(b))
		}
	}
}
