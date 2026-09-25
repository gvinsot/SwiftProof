package harness

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gvinsot/SwiftProof/app/internal/model"
)

// dockerRunFixture builds a harness on a small Go module whose baseline and
// candidate differ only in cart/cart.go, and records the name of every
// container it launches.
func dockerRunFixture(t *testing.T, image, candidateCart string) (*Harness, *[]string) {
	t.Helper()
	base, head := t.TempDir(), t.TempDir()
	files := map[string]string{
		"go.mod":       "module example.test/shop\n\ngo 1.23.0\n",
		"cart/cart.go": "package cart\n\nfunc Total(prices []int) int {\n\tsum := 0\n\tfor _, p := range prices {\n\t\tsum += p\n\t}\n\treturn sum\n}\n\nfunc Count(prices []int) int { return len(prices) }\n",
		"cart/cart_test.go": `package cart

import "testing"

func TestTotal(t *testing.T) {
	if got := Total([]int{2, 3}); got != 5 {
		t.Fatalf("Total = %d, want 5", got)
	}
}

func TestCount(t *testing.T) {
	if got := Count([]int{2, 3}); got != 2 {
		t.Fatalf("Count = %d, want 2", got)
	}
}
`,
	}
	for _, dir := range []string{base, head} {
		for path, content := range files {
			if err := os.MkdirAll(filepath.Join(dir, filepath.Dir(path)), 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, path), []byte(content), 0644); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := os.WriteFile(filepath.Join(head, "cart", "cart.go"), []byte(candidateCart), 0644); err != nil {
		t.Fatal(err)
	}
	h, err := New(Options{BaseDir: base, CandidateDir: head, ArtifactDir: t.TempDir(), Image: image, Timeout: 3 * time.Minute, MaxRuntime: 20 * time.Minute, MaxOutputBytes: 64 * 1024})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.Close() })
	var names []string
	execute := h.execute
	h.execute = func(ctx context.Context, name string, args []string, out io.Writer) execution {
		names = append(names, name)
		return execute(ctx, name, args, out)
	}
	return h, &names
}

// assertNoContainers checks that none of the containers this test launched
// survived; other agents' containers on the host are not considered.
func assertNoContainers(t *testing.T, names []string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	for _, name := range names {
		out, err := exec.CommandContext(ctx, "docker", "ps", "-a", "--filter", "name=^/"+name+"$", "--format", "{{.Names}}").Output()
		if err != nil {
			t.Fatal(err)
		}
		if strings.TrimSpace(string(out)) != "" {
			t.Errorf("container %s survived", name)
		}
	}
}

const brokenTotal = "package cart\n\nfunc Total(prices []int) int {\n\tsum := 0\n\tfor i := 1; i < len(prices); i++ {\n\t\tsum += prices[i]\n\t}\n\treturn sum\n}\n\nfunc Count(prices []int) int { return len(prices) }\n"

func TestDockerRunOptionsTimeoutTeeLedgerAndCache(t *testing.T) {
	image := os.Getenv("SWIFTPROOF_TEST_DOCKER_IMAGE")
	if image == "" {
		t.Skip("set SWIFTPROOF_TEST_DOCKER_IMAGE to a preloaded golang Linux image")
	}
	h, names := dockerRunFixture(t, image, brokenTotal)
	ctx := context.Background()

	// A tightened timeout ends the container as TIMEOUT and is what is charged.
	started := time.Now()
	c, _, _ := runLocked(h, ctx, "test", h.candidate, []string{"sh", "-c", "sleep 60"}, runOptions{timeout: 3 * time.Second})
	if c.Status != "TIMEOUT" || time.Since(started) > 45*time.Second {
		t.Fatalf("tightened timeout: %+v after %v", c, time.Since(started))
	}
	if h.reserved != 0 || h.spent < 3*time.Second {
		t.Fatalf("budget after timeout: reserved %v spent %v", h.reserved, h.spent)
	}

	// The tee receives the whole stream while the recorded log stays bounded.
	h.opts.MaxOutputBytes = 1024
	var tee bytes.Buffer
	overflow := false
	script := `i=0; while [ $i -lt 2000 ]; do echo "line-$i-................................................"; i=$((i+1)); done; exit 3`
	c, _, _ = runLocked(h, ctx, model.CheckMutant, h.candidate, []string{"sh", "-c", script}, runOptions{tee: &tee, teeOverflow: &overflow, ledger: ledgerMutation})
	h.opts.MaxOutputBytes = 64 * 1024
	if c.ID != "mutation-check-1" || c.Status != "FAIL" || c.ExitCode != 3 || !c.Truncated || len(c.Output) > 1024 {
		t.Fatalf("mutation-ledger run: %+v", c)
	}
	if !strings.Contains(tee.String(), "line-0-") || !strings.Contains(tee.String(), "line-1999-") || strings.Count(tee.String(), "\n") != 2000 || overflow {
		t.Fatalf("tee got %d bytes (overflow %v)", tee.Len(), overflow)
	}
	if len(h.Checks()) != 1 || len(h.MutationChecks()) != 1 {
		t.Fatalf("ledgers %d / %d", len(h.Checks()), len(h.MutationChecks()))
	}

	// The cache replays a baseline run only after two agreeing live runs.
	m := useMemoryCache(h)
	command := []string{"sh", "-c", "cat /workspace/cart/cart.go | wc -l && echo baseline-ok"}
	before := len(*names)
	var runs []model.Check
	for i := 0; i < 3; i++ {
		c, _, _ := runLocked(h, ctx, model.CheckGeneratedBase, h.base, command, runOptions{})
		runs = append(runs, c)
	}
	if len(*names)-before != 2 {
		t.Fatalf("%d containers for three eligible runs, want 2", len(*names)-before)
	}
	if runs[0].Cache == nil || runs[1].Cache == nil || runs[2].Cache == nil {
		t.Fatalf("cache provenance missing: %+v / %+v / %+v", runs[0], runs[1], runs[2])
	}
	if runs[0].Status != "PASS" || runs[0].Cache.LiveRuns != 1 || runs[1].Cache.LiveRuns != 2 || !runs[2].Replayed() {
		t.Fatalf("cache sequence: %+v / %+v / %+v", runs[0].Cache, runs[1].Cache, runs[2].Cache)
	}
	if runs[2].Output != runs[1].Output || !strings.Contains(runs[2].Output, "baseline-ok") || runs[2].DurationMS != 0 {
		t.Fatalf("replayed output %q", runs[2].Output)
	}
	if len(m.keys()) != 1 {
		t.Fatalf("keys %v", m.keys())
	}
	// A candidate-side run of the same command is always executed.
	c, _, _ = runLocked(h, ctx, model.CheckGeneratedCandidate, h.candidate, command, runOptions{})
	if c.Status != "PASS" || c.Cache != nil || len(*names)-before != 3 {
		t.Fatalf("candidate run: %+v", c)
	}
	assertNoContainers(t, *names)
}

func TestDockerExistingTestOutcomesFromRealGoTest(t *testing.T) {
	image := os.Getenv("SWIFTPROOF_TEST_DOCKER_IMAGE")
	if image == "" {
		t.Skip("set SWIFTPROOF_TEST_DOCKER_IMAGE to a preloaded golang Linux image")
	}
	h, names := dockerRunFixture(t, image, brokenTotal)
	ctx := context.Background()
	command := append([]string{"go", "test", "-json", "-count=1", "-run", "^(TestTotal|TestCount)$"}, "./cart")
	base, _, _ := runLocked(h, ctx, model.CheckBaseTestBase, h.base, command, runOptions{})
	if base.Status != "PASS" {
		t.Fatalf("baseline run: %+v", base)
	}
	if action, pkg := GoTestOutcome(base.Output, "TestTotal"); action != "pass" || pkg != "example.test/shop/cart" {
		t.Fatalf("baseline outcome (%q, %q)", action, pkg)
	}

	// The candidate tree breaks Total: TestTotal fails, and its passing sibling
	// inside the same FAIL check stays UNVERIFIED.
	candidate, _, _ := runLocked(h, ctx, model.CheckBaseTestHybrid, h.candidate, command, runOptions{})
	if candidate.Status != "FAIL" || candidate.ExitCode != 1 {
		t.Fatalf("candidate run: %+v", candidate)
	}
	if status, reason := ClassifyExistingTest(base, candidate, "TestTotal"); status != model.StatusFailsOnCandidate {
		t.Fatalf("TestTotal: %s %s", status, reason)
	}
	if status, _ := ClassifyExistingTest(base, candidate, "TestCount"); status != model.StatusUnverified {
		t.Fatalf("TestCount inside a FAIL check: %s", status)
	}

	// A private copy with a correct Total passes both tests.
	h.mu.Lock()
	fixed, cleanup, err := h.privateCopy("hybrid-")
	h.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	original, err := os.ReadFile(filepath.Join(h.base, "cart", "cart.go"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fixed, "cart", "cart.go"), original, 0644); err != nil {
		t.Fatal(err)
	}
	passing, _, _ := runLocked(h, ctx, model.CheckBaseTestHybrid, fixed, command, runOptions{})
	for _, name := range []string{"TestTotal", "TestCount"} {
		if status, reason := ClassifyExistingTest(base, passing, name); status != model.StatusPassesOnCandidate {
			t.Fatalf("%s on a passing tree: %s %s (%+v)", name, status, reason, passing)
		}
	}

	// A tree that does not build is a FAIL check (not ERROR) and UNVERIFIED.
	if err := os.WriteFile(filepath.Join(fixed, "cart", "cart.go"), []byte("package cart\n\nfunc Total(prices []int) int { return undefinedName }\n\nfunc Count(prices []int) int { return len(prices) }\n"), 0644); err != nil {
		t.Fatal(err)
	}
	broken, _, _ := runLocked(h, ctx, model.CheckBaseTestHybrid, fixed, command, runOptions{})
	if broken.Status != "FAIL" {
		t.Fatalf("non-building tree: %+v", broken)
	}
	if status, reason := ClassifyExistingTest(base, broken, "TestTotal"); status != model.StatusUnverified || reason != reasonCandidateBuild {
		t.Fatalf("non-building tree: %s %q\n%s", status, reason, broken.Output)
	}
	// The private copy never reached the candidate snapshot.
	if b, _ := os.ReadFile(filepath.Join(h.candidate, "cart", "cart.go")); string(b) != brokenTotal {
		t.Fatal("the private copy aliased the candidate snapshot")
	}
	assertNoContainers(t, *names)
}
