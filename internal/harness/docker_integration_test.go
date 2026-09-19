package harness

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
