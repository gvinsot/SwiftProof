package harness

// Regression guard for run.go (§3.3): timeout tightening, ceiling, atomic
// reservation, tee cap, mutation ledger, deadline, and the execution-cache
// consult/store point. F7b restructures run.go; these tests must pass
// unchanged.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gvinsot/SwiftProof/app/internal/coverage"
	"github.com/gvinsot/SwiftProof/app/internal/model"
)

var baseCommand = []string{"go", "test", "-json", "./pkg"}

// runLocked runs one command as a feature stage would: holding h.mu.
func runLocked(h *Harness, ctx context.Context, kind, dir string, command []string, o runOptions) (model.Check, []byte, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.runWithOptions(ctx, kind, dir, command, o)
}

// runBase runs the fixed baseline-side command on h.base.
func runBase(h *Harness, o runOptions) model.Check {
	c, _, _ := runLocked(h, context.Background(), model.CheckGeneratedBase, h.base, baseCommand, o)
	return c
}

// countingExec replaces the executor with one that writes output and returns
// the exit code of the call, counting calls.
func countingExec(h *Harness, output string, exits ...int) *int {
	calls := 0
	h.execute = func(_ context.Context, _ string, _ []string, out io.Writer) execution {
		exit := 0
		if calls < len(exits) {
			exit = exits[calls]
		} else if len(exits) > 0 {
			exit = exits[len(exits)-1]
		}
		calls++
		fmt.Fprint(out, output)
		return execution{ExitCode: exit}
	}
	return &calls
}

func deadlineRemaining(t *testing.T, ctx context.Context) time.Duration {
	t.Helper()
	deadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("run context has no deadline")
	}
	return time.Until(deadline)
}

func TestRunTimeoutTightensNeverLoosens(t *testing.T) {
	h := fixture(t)
	h.opts.Timeout = time.Minute
	var remaining time.Duration
	h.execute = func(ctx context.Context, _ string, _ []string, _ io.Writer) execution {
		remaining = deadlineRemaining(t, ctx)
		return execution{ExitCode: 0}
	}
	for _, tc := range []struct {
		name      string
		o, expect time.Duration
	}{
		{"policy_timeout", 0, time.Minute},
		{"tightened", 5 * time.Second, 5 * time.Second},
		{"never_loosened", 2 * time.Minute, time.Minute},
		{"negative_ignored", -time.Second, time.Minute},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, _, _ := runLocked(h, context.Background(), "test", h.candidate, baseCommand, runOptions{timeout: tc.o})
			if c.Status != "PASS" {
				t.Fatalf("run did not execute: %+v", c)
			}
			if remaining > tc.expect || remaining < tc.expect-10*time.Second {
				t.Fatalf("per-run timeout %v, want %v", remaining, tc.expect)
			}
		})
	}
}

func TestRunCeilingLimitsTheBudget(t *testing.T) {
	h := fixture(t)
	h.opts.MaxRuntime = 10 * time.Minute
	called := 0
	var remaining time.Duration
	h.execute = func(ctx context.Context, _ string, _ []string, _ io.Writer) execution {
		called++
		remaining = deadlineRemaining(t, ctx)
		return execution{ExitCode: 0}
	}
	run := func(spent time.Duration, o runOptions) model.Check {
		h.mu.Lock()
		h.spent = spent
		h.mu.Unlock()
		c, _, _ := runLocked(h, context.Background(), "test", h.candidate, baseCommand, o)
		return c
	}
	if c := run(0, runOptions{ceiling: 3 * time.Second}); c.Status != "PASS" || remaining > 3*time.Second {
		t.Fatalf("ceiling did not bound the run: %+v, timeout %v", c, remaining)
	}
	if c := run(0, runOptions{ceiling: time.Hour}); c.Status != "PASS" || remaining > time.Minute || remaining < 50*time.Second {
		t.Fatalf("a ceiling above MaxRuntime changed the policy timeout: %+v, timeout %v", c, remaining)
	}
	before := called
	if c := run(3*time.Second, runOptions{ceiling: 3 * time.Second}); c.Status != "SKIPPED" || c.Output != budgetReservedText {
		t.Fatalf("reserved budget: %+v", c)
	}
	if c := run(10*time.Minute, runOptions{ceiling: 3 * time.Second}); c.Status != "SKIPPED" || c.Output != budgetExhaustedText {
		t.Fatalf("exhausted budget under a ceiling: %+v", c)
	}
	if c := run(10*time.Minute, runOptions{}); c.Status != "SKIPPED" || c.Output != budgetExhaustedText {
		t.Fatalf("exhausted budget: %+v", c)
	}
	if called != before {
		t.Fatal("a skipped run reached the executor")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.reserved != 0 {
		t.Fatalf("a skipped run left %v reserved", h.reserved)
	}
}

// Sequentially, reservation equals v0.2's "remaining at launch" accounting.
func TestRunSequentialBudgetMatchesRemainingAtLaunch(t *testing.T) {
	h := fixture(t)
	h.opts.Timeout = 60 * time.Millisecond
	h.opts.MaxRuntime = 100 * time.Millisecond
	var timeouts []time.Duration
	h.execute = func(ctx context.Context, _ string, _ []string, _ io.Writer) execution {
		timeouts = append(timeouts, deadlineRemaining(t, ctx))
		<-ctx.Done()
		return execution{ExitCode: -1, TimedOut: true}
	}
	first := h.Run(context.Background(), "test")
	second := h.Run(context.Background(), "test")
	third := h.Run(context.Background(), "test")
	if first.Status != "TIMEOUT" || third.Status != "SKIPPED" || third.Output != budgetExhaustedText {
		t.Fatalf("statuses %s %s %s", first.Status, second.Status, third.Status)
	}
	if timeouts[0] > 60*time.Millisecond {
		t.Fatalf("first run timeout %v exceeds the policy timeout", timeouts[0])
	}
	if second.Status == "TIMEOUT" && (len(timeouts) != 2 || timeouts[1] > 40*time.Millisecond) {
		t.Fatalf("second run was not limited to the remaining budget: %v", timeouts)
	}
	b := h.Budget()
	if b.MaxRuntimeMS != 100 || b.SpentMS < 100 || b.ReviewerReserveMS != 0 {
		t.Fatalf("budget %+v", b)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.reserved != 0 {
		t.Fatalf("%v still reserved", h.reserved)
	}
}

func TestRunReservationIsReleasedAndElapsedCharged(t *testing.T) {
	h := fixture(t)
	h.opts.ReviewerReserve = 5 * time.Minute
	var inFlight time.Duration
	h.execute = func(_ context.Context, _ string, _ []string, _ io.Writer) execution {
		inFlight = h.reserved // read while the caller holds h.mu
		time.Sleep(20 * time.Millisecond)
		return execution{ExitCode: 0}
	}
	c, _, _ := runLocked(h, context.Background(), "test", h.candidate, baseCommand, runOptions{timeout: 7 * time.Second})
	if c.Status != "PASS" || inFlight != 7*time.Second {
		t.Fatalf("status %s, reserved in flight %v", c.Status, inFlight)
	}
	h.mu.Lock()
	reserved, spent := h.reserved, h.spent
	h.mu.Unlock()
	if reserved != 0 || spent < 20*time.Millisecond || spent > 7*time.Second {
		t.Fatalf("reserved %v spent %v", reserved, spent)
	}
	if b := h.Budget(); b.ReviewerReserveMS != 300000 || b.MaxRuntimeMS != 600000 || b.SpentMS != spent.Milliseconds() || b.DeadlineReached {
		t.Fatalf("budget %+v", b)
	}
}

// Concurrent reservers (F7b's parallel launches) never hold more than the
// remaining budget between them.
func TestConcurrentReservationsNeverExceedBudget(t *testing.T) {
	for _, tc := range []struct {
		name          string
		ceiling, want time.Duration
		grants        int
	}{
		{"whole_budget", 0, 100 * time.Millisecond, 2},
		{"reviewer_ceiling", 50 * time.Millisecond, 50 * time.Millisecond, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := fixture(t)
			h.opts.MaxRuntime = 100 * time.Millisecond
			const n = 8
			var wg, allReserved sync.WaitGroup
			allReserved.Add(n)
			granted := make([]time.Duration, n)
			var peak time.Duration
			for i := 0; i < n; i++ {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					h.mu.Lock()
					d, skipped := h.reserveRun(60*time.Millisecond, tc.ceiling)
					if skipped == "" {
						granted[i] = d
					}
					if h.reserved > peak {
						peak = h.reserved
					}
					if h.reserved+h.spent > h.opts.MaxRuntime {
						t.Errorf("reservations %v exceed the remaining budget", h.reserved)
					}
					h.mu.Unlock()
					allReserved.Done()
					allReserved.Wait() // every reserver holds its reservation at the same time
					h.mu.Lock()
					if skipped == "" {
						h.releaseRun(d, d)
					}
					h.mu.Unlock()
				}(i)
			}
			wg.Wait()
			var total time.Duration
			grants := 0
			for _, d := range granted {
				if d > 0 {
					grants++
					total += d
				}
			}
			if total != tc.want || grants != tc.grants || peak != tc.want {
				t.Fatalf("granted %v in %d reservations (peak %v), want %v in %d", total, grants, peak, tc.want, tc.grants)
			}
			if h.reserved != 0 || h.spent != tc.want {
				t.Fatalf("after release: reserved %v spent %v", h.reserved, h.spent)
			}
		})
	}
}

func TestRunDeadlineSkipsUnstartedRuns(t *testing.T) {
	h := fixture(t)
	calls := countingExec(h, "ok\n")
	expired, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	c, _, _ := runLocked(h, expired, "test", h.candidate, baseCommand, runOptions{})
	if c.Status != "SKIPPED" || c.Output != deadlineText || *calls != 0 {
		t.Fatalf("a run started after the overall deadline: %+v (calls %d)", c, *calls)
	}
	// The text names both limits a run context can carry, so a reviewer call
	// made after reviewer.timeout_seconds is not blamed on --deadline alone.
	if !strings.Contains(c.Output, "--deadline") || !strings.Contains(c.Output, "reviewer time limit") {
		t.Fatalf("deadline text %q", c.Output)
	}
	// A cancellation that is not a deadline keeps the v0.2 path: the executor
	// sees the cancelled context and the run is recorded as it ended.
	cancelled, stop := context.WithCancel(context.Background())
	stop()
	h.execute = func(ctx context.Context, _ string, _ []string, _ io.Writer) execution {
		if ctx.Err() == nil {
			t.Error("executor context not cancelled")
		}
		return execution{ExitCode: -1, TimedOut: true}
	}
	if c, _, _ := runLocked(h, cancelled, "test", h.candidate, baseCommand, runOptions{}); c.Status != "TIMEOUT" {
		t.Fatalf("cancelled run: %+v", c)
	}
}

type countingWriter struct {
	n   int64
	err error
}

func (w *countingWriter) Write(p []byte) (int, error) {
	w.n += int64(len(p))
	if w.err != nil {
		return 0, w.err
	}
	return len(p), nil
}

func TestTeeGetsTheStreamBeyondTheRecordedLog(t *testing.T) {
	h := fixture(t)
	h.opts.MaxOutputBytes = 256
	stream := strings.Repeat("0123456789", 1000)
	h.execute = func(_ context.Context, _ string, _ []string, out io.Writer) execution {
		for i := 0; i < len(stream); i += 1000 {
			if _, err := io.WriteString(out, stream[i:i+1000]); err != nil {
				t.Errorf("log writer failed: %v", err)
			}
		}
		return execution{ExitCode: 1}
	}
	var tee bytes.Buffer
	overflow := false
	c, _, _ := runLocked(h, context.Background(), model.CheckMutant, h.candidate, baseCommand, runOptions{tee: &tee, teeOverflow: &overflow, ledger: ledgerMutation})
	if c.Status != "FAIL" || !c.Truncated || len(c.Output) > 256 {
		t.Fatalf("recorded log: %+v", c)
	}
	if tee.String() != stream || overflow {
		t.Fatalf("tee got %d bytes (overflow %v), want the full %d-byte stream", tee.Len(), overflow, len(stream))
	}
	// A failing tee never disturbs the recorded log or the run.
	h.opts.MaxOutputBytes = 32 * 1024
	failing := &countingWriter{err: errors.New("consumer gone")}
	c, _, _ = runLocked(h, context.Background(), "test", h.candidate, baseCommand, runOptions{tee: failing})
	if c.Status != "FAIL" || c.Output != stream || failing.n != 1000 {
		t.Fatalf("a failing tee changed the run: status %s, %d bytes recorded, tee saw %d", c.Status, len(c.Output), failing.n)
	}
}

func TestTeeCapAndOverflowFlag(t *testing.T) {
	h := fixture(t)
	chunk := make([]byte, 1<<20)
	h.execute = func(_ context.Context, _ string, _ []string, out io.Writer) execution {
		for i := 0; i < teeLimit>>20+1; i++ {
			if _, err := out.Write(chunk); err != nil {
				t.Errorf("log writer failed past the tee cap: %v", err)
			}
		}
		return execution{ExitCode: 0}
	}
	tee := &countingWriter{}
	overflow := false
	c, _, _ := runLocked(h, context.Background(), "test", h.candidate, baseCommand, runOptions{tee: tee, teeOverflow: &overflow})
	if c.Status != "PASS" || tee.n != teeLimit || !overflow {
		t.Fatalf("tee received %d bytes (overflow %v), want exactly %d and overflow", tee.n, overflow, teeLimit)
	}
	// The cap applies per writer; exactly the limit is not an overflow.
	exact, flag := &countingWriter{}, false
	w := &cappedWriter{w: exact, remaining: 8, overflow: &flag}
	for _, s := range []string{"abc", "defgh"} {
		if n, err := w.Write([]byte(s)); n != len(s) || err != nil {
			t.Fatalf("capped write: %d %v", n, err)
		}
	}
	if exact.n != 8 || flag {
		t.Fatalf("exact cap: %d bytes, overflow %v", exact.n, flag)
	}
	if n, err := w.Write([]byte("i")); n != 1 || err != nil || !flag || exact.n != 8 {
		t.Fatalf("past the cap: n=%d err=%v overflow=%v forwarded=%d", n, err, flag, exact.n)
	}
}

func TestTeeReceivesCaptureRunLogOnly(t *testing.T) {
	h := fixture(t)
	h.executeCapture = func(_ context.Context, _ string, _ []string, log, payload io.Writer) execution {
		fmt.Fprint(log, "log line\n")
		fmt.Fprint(payload, coverageFrame("payload"))
		return execution{ExitCode: 0}
	}
	var tee bytes.Buffer
	_, payload, truncated := runLocked(h, context.Background(), "test", h.candidate, baseCommand, runOptions{capture: ResultsPath, tee: &tee})
	if tee.String() != "log line\n" || truncated || !strings.Contains(string(payload), "payload") {
		t.Fatalf("tee %q payload %q", tee.String(), payload)
	}
}

func TestMutationLedgerIsSeparate(t *testing.T) {
	h := fixture(t)
	calls := countingExec(h, "mutant log\n", 1)
	m, _, _ := runLocked(h, context.Background(), model.CheckMutant, h.candidate, baseCommand, runOptions{ledger: ledgerMutation})
	if m.ID != "mutation-check-1" || m.Status != "FAIL" {
		t.Fatalf("mutation check %+v", m)
	}
	if len(h.Checks()) != 0 {
		t.Fatal("a mutation check entered the main ledger")
	}
	mutation := h.MutationChecks()
	if len(mutation) != 1 || mutation[0].ID != "mutation-check-1" || mutation[0].Kind != model.CheckMutant {
		t.Fatalf("mutation ledger %+v", mutation)
	}
	a, ok := artifactByKind(h, model.ArtifactMutationCheckOutput)
	if !ok || !strings.HasSuffix(a.Path, "-mutation-check-1.log") {
		t.Fatalf("mutation log artifact %+v", h.Artifacts())
	}
	if _, ok := artifactByKind(h, "check_output"); ok {
		t.Fatal("a mutation log was filed as a main-ledger check output")
	}
	mutation[0].Command[0] = "tampered"
	if h.MutationChecks()[0].Command[0] != "go" {
		t.Fatal("MutationChecks shares its Command slice")
	}
	if c := h.Run(context.Background(), "test"); c.ID != "check-1" {
		t.Fatalf("the mutation ledger shifted main check IDs: %s", c.ID)
	}
	second, _, _ := runLocked(h, context.Background(), model.CheckMutationControl, h.candidate, baseCommand, runOptions{ledger: ledgerMutation})
	if second.ID != "mutation-check-2" {
		t.Fatalf("second mutation check %s", second.ID)
	}
	before := *calls
	bogus, _, _ := runLocked(h, context.Background(), "test", h.candidate, baseCommand, runOptions{ledger: "bogus"})
	if bogus.Status != "ERROR" || bogus.ID != "check-2" || *calls != before {
		t.Fatalf("unknown ledger: %+v (executor calls %d -> %d)", bogus, before, *calls)
	}
}

// Log text candidate code writes never makes a candidate-side v0.4 run ERROR:
// the inherited v0.2 log rules apply only to the v0.2 kinds, to
// generated_test_intent and to the baseline-side v0.4 kinds (§1.17).
func TestLogTextDecidesErrorOnlyForTrustedLogKinds(t *testing.T) {
	const forged = "fork/exec /tmp/x: permission denied\n[setup failed]\nFAIL\n"
	for _, tt := range []struct {
		kind, ledger, want string
	}{
		{model.CheckFuzzCandidate, "", "FAIL"},
		{model.CheckFuzzCandidateConfirm, "", "FAIL"},
		{model.CheckBaseTestHybrid, "", "FAIL"},
		{model.CheckImpactedTestCandidate, "", "FAIL"},
		{model.CheckMutant, ledgerMutation, "FAIL"},
		{model.CheckMutationControl, ledgerMutation, "FAIL"},
		{"unlisted_kind", "", "FAIL"},
		// Unchanged v0.2 behavior, and the kinds whose log is not candidate-written.
		{"test", "", "ERROR"},
		{model.CheckExistingTest, "", "ERROR"},
		{model.CheckGeneratedCandidate, "", "ERROR"},
		{model.CheckGeneratedIntent, "", "ERROR"},
		{model.CheckGeneratedBase, "", "ERROR"},
		{model.CheckGeneratedBaseRepeat, "", "ERROR"},
		{model.CheckFuzzBase, "", "ERROR"},
		{model.CheckFuzzBaseConfirm, "", "ERROR"},
		{model.CheckBaseTestBase, "", "ERROR"},
		{model.CheckImpactedTestBase, "", "ERROR"},
	} {
		t.Run(tt.kind, func(t *testing.T) {
			h := fixture(t)
			countingExec(h, forged, 1)
			c, _, _ := runLocked(h, context.Background(), tt.kind, h.candidate, baseCommand, runOptions{ledger: tt.ledger})
			if c.Status != tt.want {
				t.Fatalf("%s with a forged setup-failure log: %s, want %s", tt.kind, c.Status, tt.want)
			}
		})
	}
	// Infrastructure causes stay ERROR for every kind.
	for _, kind := range []string{model.CheckFuzzCandidate, model.CheckBaseTestHybrid, model.CheckImpactedTestCandidate, model.CheckMutant} {
		h := fixture(t)
		countingExec(h, "ok\n", 125)
		if c, _, _ := runLocked(h, context.Background(), kind, h.candidate, baseCommand, runOptions{}); c.Status != "ERROR" {
			t.Fatalf("%s with exit 125: %s", kind, c.Status)
		}
		h.execute = func(context.Context, string, []string, io.Writer) execution {
			return execution{ExitCode: -1, Err: errors.New("docker: cannot connect")}
		}
		if c, _, _ := runLocked(h, context.Background(), kind, h.candidate, baseCommand, runOptions{}); c.Status != "ERROR" {
			t.Fatalf("%s with an executor error: %s", kind, c.Status)
		}
	}
}

func TestChecksDeepCopyCommandAndCache(t *testing.T) {
	h := fixture(t)
	h.mu.Lock()
	h.checks = append(h.checks, model.Check{ID: "check-1", Kind: model.CheckGeneratedBase, Command: []string{"go", "test"}, Cache: &model.CheckCache{Status: model.CacheHit, LiveRuns: 2}})
	h.mutationChecks = append(h.mutationChecks, model.Check{ID: "mutation-check-1", Command: []string{"go"}, Cache: &model.CheckCache{Status: model.CacheStored}})
	h.mu.Unlock()
	checks := h.Checks()
	checks[0].Command[0] = "rm"
	checks[0].Cache.Status = model.CacheStored
	checks[0].Cache.LiveRuns = 99
	again := h.Checks()
	if again[0].Command[0] != "go" || again[0].Cache.Status != model.CacheHit || again[0].Cache.LiveRuns != 2 || !again[0].Replayed() {
		t.Fatalf("Checks shares state with the ledger: %+v %+v", again[0], again[0].Cache)
	}
	mutation := h.MutationChecks()
	mutation[0].Cache.Status = model.CacheHit
	if h.MutationChecks()[0].Cache.Status != model.CacheStored {
		t.Fatal("MutationChecks shares its Cache")
	}
}

func TestRunChecksKeepsConfiguredOrderAndAudit(t *testing.T) {
	h := fixture(t)
	h.opts.Commands["build"] = []string{"go", "build", "./..."}
	countingExec(h, "ok\n")
	checks := h.RunChecks(context.Background(), []string{"test", "build"})
	if len(checks) != 2 || checks[0].ID != "check-1" || checks[0].Kind != "test" || checks[1].ID != "check-2" || checks[1].Kind != "build" {
		t.Fatalf("checks %+v", checks)
	}
	var tools []string
	for _, e := range h.Audit() {
		tools = append(tools, e.Tool)
	}
	if strings.Join(tools, ",") != "run_test,run_build" {
		t.Fatalf("audit %v", tools)
	}
}

// --- execution cache consult/store point -------------------------------------

func auditTools(h *Harness) []string {
	var tools []string
	for _, e := range h.Audit() {
		tools = append(tools, e.Tool)
	}
	return tools
}

func TestCacheNeverServesBeforeTwoAgreeingLiveRuns(t *testing.T) {
	h := fixture(t)
	m := useMemoryCache(h)
	calls := countingExec(h, "base run output\n", 0)
	first := runBase(h, runOptions{})
	if first.Cache == nil || first.Cache.Status != model.CacheStored || first.Cache.LiveRuns != 1 || first.Replayed() {
		t.Fatalf("first live run: %+v %+v", first, first.Cache)
	}
	keys := m.keys()
	if len(keys) != 1 || keys[0] != first.Cache.Key || !cacheKeyPattern.MatchString(keys[0]) {
		t.Fatalf("stored keys %v", keys)
	}
	entry, _ := m.entry(keys[0])
	sum := sha256.Sum256(entry.Preimage)
	if hex.EncodeToString(sum[:]) != entry.Key || entry.LiveRuns != 1 || entry.RecordedRun != h.runID || entry.RecordedCheck != first.ID || entry.Output != first.Output {
		t.Fatalf("stored entry %+v", entry)
	}
	if strings.Contains(string(entry.Preimage), "go test") || strings.Contains(string(entry.Preimage), "./pkg") {
		t.Fatalf("the preimage holds raw argv: %s", entry.Preimage)
	}
	second := runBase(h, runOptions{})
	if *calls != 2 || second.Cache == nil || second.Cache.Status != model.CacheStored || second.Cache.LiveRuns != 2 || second.Replayed() {
		t.Fatalf("an entry was served after one live run: calls %d, %+v", *calls, second.Cache)
	}
	h.mu.Lock()
	spent := h.spent
	h.mu.Unlock()
	third := runBase(h, runOptions{})
	if *calls != 2 {
		t.Fatal("a servable entry was executed again")
	}
	if !third.Replayed() || third.ID != "check-3" || third.Status != "PASS" || third.DurationMS != 0 || third.Output != second.Output {
		t.Fatalf("replayed check %+v", third)
	}
	if c := third.Cache; c.Key != keys[0] || c.LiveRuns != 2 || c.RecordedCheck != second.ID || c.RecordedRun != h.runID || c.RecordedDurationMS != second.DurationMS {
		t.Fatalf("replay provenance %+v", c)
	}
	h.mu.Lock()
	if h.spent != spent || h.reserved != 0 {
		t.Errorf("a replay was charged: spent %v -> %v, reserved %v", spent, h.spent, h.reserved)
	}
	counts := h.cacheCounts
	h.mu.Unlock()
	if counts.Hits != 1 || counts.Stored != 2 || counts.Misses != 2 || counts.Uncacheable != 0 || counts.Contradicted != 0 {
		t.Fatalf("counters %+v", counts)
	}
	tools := auditTools(h)
	if len(tools) != 1 || tools[0] != "stage:execution_cache" || h.Audit()[0].Status != "HIT" || !strings.Contains(h.Audit()[0].Arguments, third.ID) {
		t.Fatalf("replay audit %v %+v", tools, h.Audit())
	}
	found := false
	for _, a := range h.Artifacts() {
		if strings.HasSuffix(a.Path, "-check-3.log") {
			found = true
			b, err := os.ReadFile(a.Path)
			if err != nil || string(b) != third.Output || a.Kind != "check_output" {
				t.Fatalf("replayed log artifact %q %v", b, err)
			}
		}
	}
	if !found {
		t.Fatal("the replayed log was not re-saved as check-3.log")
	}
}

// The execution summary reports what the harness counted itself plus what the
// store reports; neither half may be dropped (F7a replaces Execution).
func TestExecutionReportsHarnessAndStoreCounters(t *testing.T) {
	h := fixture(t)
	m := useMemoryCache(h)
	countingExec(h, "base run output\n", 0)
	for i := 0; i < 3; i++ { // miss (stored), miss (stored), hit
		runBase(h, runOptions{})
	}
	m.mu.Lock()
	m.stats = model.ExecutionCache{Rejected: 2, Evicted: 1}
	m.mu.Unlock()
	c := h.Execution().Cache
	if c.Hits != 1 || c.Misses != 2 || c.Stored != 2 || c.Rejected != 2 || c.Evicted != 1 || c.Uncacheable != 0 || c.WriteFailures != 0 || c.Contradicted != 0 {
		t.Fatalf("execution cache counters %+v", c)
	}
}

func TestCacheContradictionEvictsTheEntry(t *testing.T) {
	h := fixture(t)
	m := useMemoryCache(h)
	countingExec(h, "output\n", 0, 1, 1)
	runBase(h, runOptions{})
	contradicting := runBase(h, runOptions{})
	if contradicting.Status != "FAIL" || contradicting.Cache != nil || len(m.keys()) != 0 {
		t.Fatalf("a disagreeing live run left an entry: %+v %v", contradicting.Cache, m.keys())
	}
	h.mu.Lock()
	counts := h.cacheCounts
	h.mu.Unlock()
	if counts.Contradicted != 1 || counts.Evicted != 1 || counts.Stored != 1 {
		t.Fatalf("counters %+v", counts)
	}
	fresh := runBase(h, runOptions{})
	if fresh.Cache == nil || fresh.Cache.LiveRuns != 1 {
		t.Fatalf("the next live run did not start a fresh entry: %+v", fresh.Cache)
	}
	// An entry already marked contradicted is never served nor extended.
	m.update(fresh.Cache.Key, func(e *CacheEntry) { e.LiveRuns, e.Contradicted = 5, true })
	again := runBase(h, runOptions{})
	if again.Replayed() || again.Cache != nil || len(m.keys()) != 0 {
		t.Fatalf("a contradicted entry was served or kept: %+v %v", again.Cache, m.keys())
	}
}

func TestCacheLiveRunIsNeverServedButWritesThrough(t *testing.T) {
	h := fixture(t)
	useMemoryCache(h)
	calls := countingExec(h, "output\n", 0)
	runBase(h, runOptions{})
	runBase(h, runOptions{})
	live := runBase(h, runOptions{live: true})
	if *calls != 3 || live.Replayed() || live.Cache == nil || live.Cache.Status != model.CacheStored || live.Cache.LiveRuns != 3 {
		t.Fatalf("live run: calls %d cache %+v", *calls, live.Cache)
	}
	replayed := runBase(h, runOptions{})
	if *calls != 3 || !replayed.Replayed() || replayed.Cache.LiveRuns != 3 || replayed.Cache.RecordedCheck != live.ID {
		t.Fatalf("after the live run: calls %d cache %+v", *calls, replayed.Cache)
	}
}

func TestCacheIneligibleRunsNeverTouchTheCache(t *testing.T) {
	h := fixture(t)
	m := useMemoryCache(h)
	countingExec(h, "output\n", 0)
	for _, run := range []struct {
		kind, dir string
		network   bool
	}{
		{model.CheckGeneratedBase, h.candidate, false},       // candidate tree
		{model.CheckGeneratedCandidate, h.base, false},       // candidate kind
		{model.CheckGeneratedBaseRepeat, h.base, false},      // distinct re-run kind
		{model.CheckFuzzBaseConfirm, h.base, false},          // distinct re-run kind
		{"test", h.base, false},                              // initial check kind
		{model.CheckGeneratedBase, h.base, true},             // network on
		{model.CheckGeneratedBase, t.TempDir() + "x", false}, // another tree
	} {
		h.opts.Network = run.network
		runLocked(h, context.Background(), run.kind, run.dir, baseCommand, runOptions{})
	}
	h.opts.Network = false
	if m.gets != 0 || m.puts != 0 || m.deletes != 0 {
		t.Fatalf("ineligible runs used the cache: gets %d puts %d deletes %d", m.gets, m.puts, m.deletes)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.cacheCounts != (model.ExecutionCache{}) {
		t.Fatalf("ineligible runs were counted: %+v", h.cacheCounts)
	}
}

func TestCacheStoresOnlyCompletedResults(t *testing.T) {
	cases := []struct {
		name    string
		prepare func(h *Harness)
		capture bool
		stored  bool
	}{
		{"timeout", func(h *Harness) {
			h.execute = func(context.Context, string, []string, io.Writer) execution {
				return execution{ExitCode: -1, TimedOut: true}
			}
		}, false, false},
		{"executor_error", func(h *Harness) {
			h.execute = func(context.Context, string, []string, io.Writer) execution {
				return execution{ExitCode: -1, Err: errors.New("docker unavailable")}
			}
		}, false, false},
		{"infrastructure_exit", func(h *Harness) { countingExec(h, "output\n", 125) }, false, false},
		{"setup_failure", func(h *Harness) { countingExec(h, "FAIL pkg [build failed]\n", 1) }, false, false},
		{"artifact_failure", func(h *Harness) {
			countingExec(h, "output\n", 0)
			h.opts.ArtifactDir = filepath.Join(h.opts.ArtifactDir, "missing", "dir")
		}, false, false},
		{"failing_run", func(h *Harness) { countingExec(h, "output\n", 1) }, false, true},
		{"truncated_payload", func(h *Harness) {
			h.executeCapture = func(_ context.Context, _ string, _ []string, _, payload io.Writer) execution {
				fmt.Fprint(payload, strings.Repeat("x", PayloadLimit(h.opts.MaxOutputBytes)+1))
				return execution{ExitCode: 0}
			}
		}, true, false},
		{"unredactable_payload", func(h *Harness) {
			h.executeCapture = func(_ context.Context, _ string, _ []string, _, payload io.Writer) execution {
				fmt.Fprint(payload, coverageFrame("password=hunter2"))
				return execution{ExitCode: 0}
			}
		}, true, false},
		{"clean_payload", func(h *Harness) {
			h.executeCapture = func(_ context.Context, _ string, _ []string, _, payload io.Writer) execution {
				fmt.Fprint(payload, coverageFrame(`{"testResults":[]}`))
				return execution{ExitCode: 0}
			}
		}, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := fixture(t)
			m := useMemoryCache(h)
			tc.prepare(h)
			o := runOptions{}
			if tc.capture {
				o.capture = ResultsPath
			}
			c, payload, _ := runLocked(h, context.Background(), model.CheckGeneratedBase, h.base, baseCommand, o)
			if stored := len(m.keys()) == 1; stored != tc.stored || (c.Cache != nil) != tc.stored {
				t.Fatalf("stored=%v cache=%+v for a %s check", stored, c.Cache, c.Status)
			}
			h.mu.Lock()
			counts := h.cacheCounts
			h.mu.Unlock()
			if !tc.stored && counts.Uncacheable != 1 {
				t.Fatalf("an unstorable run was not counted uncacheable: %+v", counts)
			}
			if tc.stored && tc.capture {
				e, _ := m.entry(m.keys()[0])
				if !bytes.Equal(e.Payload, payload) {
					t.Fatalf("stored payload %q, returned %q", e.Payload, payload)
				}
			}
		})
	}
	// A run the budget skipped is neither stored nor counted.
	h := fixture(t)
	m := useMemoryCache(h)
	h.spent = h.opts.MaxRuntime
	c := runBase(h, runOptions{})
	if c.Status != "SKIPPED" || len(m.keys()) != 0 || h.cacheCounts.Uncacheable != 0 || m.puts != 0 {
		t.Fatalf("skipped run: %+v %+v", c, h.cacheCounts)
	}
}

func TestServableAndStorableRules(t *testing.T) {
	good := CacheEntry{Status: "PASS", ExitCode: 0, LiveRuns: 2, DurationMS: 1000}
	if !servable(good, 2*time.Second) {
		t.Fatal("a servable entry was refused")
	}
	for name, e := range map[string]CacheEntry{
		"one_live_run":        {Status: "PASS", LiveRuns: 1, DurationMS: 1},
		"contradicted":        {Status: "PASS", LiveRuns: 3, Contradicted: true},
		"duration_at_timeout": {Status: "PASS", LiveRuns: 2, DurationMS: 2000},
		"negative_duration":   {Status: "PASS", LiveRuns: 2, DurationMS: -1},
		"error_status":        {Status: "ERROR", ExitCode: 125, LiveRuns: 2},
		"timeout_status":      {Status: "TIMEOUT", ExitCode: -1, LiveRuns: 2},
		"pass_nonzero_exit":   {Status: "PASS", ExitCode: 1, LiveRuns: 2},
		"fail_zero_exit":      {Status: "FAIL", ExitCode: 0, LiveRuns: 2},
		"infra_exit":          {Status: "FAIL", ExitCode: 125, LiveRuns: 2},
		"unredacted_payload":  {Status: "PASS", LiveRuns: 2, Payload: []byte("api_key=abcdef")},
	} {
		if servable(e, 2*time.Second) {
			t.Errorf("%s: served", name)
		}
	}
	if !servable(CacheEntry{Status: "FAIL", ExitCode: 1, LiveRuns: 2, Payload: []byte("plain")}, time.Second) {
		t.Error("a FAIL entry with a clean payload was refused")
	}
	if !storable(model.Check{Status: "FAIL", ExitCode: 124}, nil, false) || !storable(model.Check{Status: "PASS"}, []byte("ok"), false) {
		t.Error("a completed result was refused")
	}
	for name, c := range map[string]model.Check{
		"error":   {Status: "ERROR", ExitCode: 125},
		"timeout": {Status: "TIMEOUT", ExitCode: -1},
		"skipped": {Status: "SKIPPED", ExitCode: -1},
		"exit":    {Status: "FAIL", ExitCode: 125},
	} {
		if storable(c, nil, false) {
			t.Errorf("%s stored", name)
		}
	}
	if storable(model.Check{Status: "PASS"}, []byte("ok"), true) || storable(model.Check{Status: "PASS"}, []byte("Bearer abcdefghijkl"), false) {
		t.Error("a cut or unredactable payload was stored")
	}
}

func TestCacheReplayRespectsTheEffectiveTimeout(t *testing.T) {
	h := fixture(t)
	m := useMemoryCache(h)
	calls := countingExec(h, "output\n", 0)
	first := runBase(h, runOptions{timeout: 2 * time.Second})
	runBase(h, runOptions{timeout: 2 * time.Second})
	m.update(first.Cache.Key, func(e *CacheEntry) { e.DurationMS = 2000 })
	if c := runBase(h, runOptions{timeout: 2 * time.Second}); c.Replayed() || *calls != 3 {
		t.Fatalf("an entry recorded at the timeout was served: %+v", c.Cache)
	}
	m.update(first.Cache.Key, func(e *CacheEntry) { e.DurationMS = 1999 })
	if c := runBase(h, runOptions{timeout: 2 * time.Second}); !c.Replayed() || *calls != 3 {
		t.Fatalf("an entry recorded below the timeout was not served: %+v", c.Cache)
	}
	// The per-run timeout is part of the key: another timeout is another entry.
	if c := runBase(h, runOptions{}); c.Replayed() || *calls != 4 || len(m.keys()) != 2 {
		t.Fatalf("a different timeout reused the entry: %+v keys %d", c.Cache, len(m.keys()))
	}
}

func TestCacheReplayIsFreeEvenWhenTheBudgetIsExhausted(t *testing.T) {
	h := fixture(t)
	useMemoryCache(h)
	calls := countingExec(h, "output\n", 0)
	runBase(h, runOptions{})
	runBase(h, runOptions{})
	h.mu.Lock()
	h.spent = h.opts.MaxRuntime
	h.mu.Unlock()
	if c := runBase(h, runOptions{}); !c.Replayed() || *calls != 2 {
		t.Fatalf("replay: %+v", c)
	}
	if c := runBase(h, runOptions{live: true}); c.Status != "SKIPPED" || *calls != 2 {
		t.Fatalf("a live run ignored the exhausted budget: %+v", c)
	}
}

func TestCacheKeyCoversTreeArgvKindAndStagedFiles(t *testing.T) {
	first, second := fixture(t), fixture(t)
	m1, m2 := useMemoryCache(first), useMemoryCache(second)
	countingExec(first, "output\n", 0)
	countingExec(second, "output\n", 0)
	a := runBase(first, runOptions{})
	b := runBase(second, runOptions{})
	if a.Cache.Key != b.Cache.Key || m1.keys()[0] != m2.keys()[0] {
		t.Fatal("identical baseline runs in two harnesses got different keys")
	}
	cleanup, err := stageEphemeral(first.base, "pkg/staged_test.go", generatedSource)
	if err != nil {
		t.Fatal(err)
	}
	staged := runBase(first, runOptions{})
	cleanup()
	c, _, _ := runLocked(first, context.Background(), model.CheckGeneratedBase, first.base, append(append([]string(nil), baseCommand...), "-v"), runOptions{})
	d, _, _ := runLocked(first, context.Background(), model.CheckBaseTestBase, first.base, baseCommand, runOptions{})
	keys := map[string]bool{a.Cache.Key: true, staged.Cache.Key: true, c.Cache.Key: true, d.Cache.Key: true}
	if len(keys) != 4 {
		t.Fatalf("staged file, argv or kind did not change the key: %v", keys)
	}
	// A tree that cannot be hashed is uncacheable and never looked up.
	third := fixture(t)
	m3 := useMemoryCache(third)
	countingExec(third, "output\n", 0)
	if err := os.Symlink(filepath.Join(third.base, "pkg", "main.go"), filepath.Join(third.base, "link.go")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if c := runBase(third, runOptions{}); c.Cache != nil || m3.gets != 0 || third.cacheCounts.Uncacheable != 1 {
		t.Fatalf("an unhashable tree was keyed: %+v gets %d counts %+v", c.Cache, m3.gets, third.cacheCounts)
	}
}

func TestCacheWriteFailuresNeverFailTheRun(t *testing.T) {
	h := fixture(t)
	m := useMemoryCache(h)
	countingExec(h, "output\n", 0, 1)
	m.putErr = errors.New("disk full")
	c := runBase(h, runOptions{})
	if c.Status != "PASS" || c.Cache != nil || h.cacheCounts.WriteFailures != 1 || h.cacheCounts.Stored != 0 {
		t.Fatalf("put failure: %+v %+v", c, h.cacheCounts)
	}
	m.putErr = nil
	runBase(h, runOptions{}) // FAIL: nothing stored yet, so this starts an entry
	m.deleteErr = errors.New("read-only")
	h.execute = func(_ context.Context, _ string, _ []string, out io.Writer) execution {
		fmt.Fprint(out, "output\n")
		return execution{ExitCode: 0}
	}
	c = runBase(h, runOptions{})
	if c.Status != "PASS" || c.Cache != nil || h.cacheCounts.WriteFailures != 2 || h.cacheCounts.Contradicted != 1 || h.cacheCounts.Evicted != 0 {
		t.Fatalf("delete failure: %+v %+v", c, h.cacheCounts)
	}
}

func TestCacheReplayReturnsThePayloadForRenormalization(t *testing.T) {
	h := tsFixture(t)
	useMemoryCache(h)
	report := jestResults("src/cart.test.ts", map[string]string{"applies the discount once": "passed"})
	captures := 0
	h.executeCapture = func(_ context.Context, _ string, _ []string, log, payload io.Writer) execution {
		captures++
		fmt.Fprint(log, "vitest log\n")
		fmt.Fprint(payload, coverageFrame(report))
		return execution{ExitCode: 0}
	}
	command := h.testCommand("src/cart.test.ts")
	var checks []model.Check
	for i := 0; i < 3; i++ {
		h.mu.Lock()
		checks = append(checks, h.runWithResultsOptions(context.Background(), model.CheckGeneratedBase, h.base, command, runOptions{}))
		h.mu.Unlock()
	}
	if captures != 2 || !checks[2].Replayed() {
		t.Fatalf("captures %d, third replayed %v", captures, checks[2].Replayed())
	}
	if checks[2].Results == "" || checks[2].Results != checks[0].Results || checks[2].Status != "PASS" {
		t.Fatalf("replayed results %q, live %q", checks[2].Results, checks[0].Results)
	}
	results := 0
	for _, a := range h.Artifacts() {
		if a.Kind == model.ArtifactTestResults {
			results++
		}
	}
	if results != 3 {
		t.Fatalf("the replayed results were not re-saved: %d test_results artifacts", results)
	}
	if got := h.Checks()[2]; got.Results != checks[2].Results || !got.Replayed() {
		t.Fatalf("ledger check %+v", got)
	}
}

// A generated experiment whose baseline is replayed keeps the replayed check
// in the ledger, with the generated file staged exactly as for the live runs.
func TestGeneratedExperimentBaselineCanBeReplayed(t *testing.T) {
	h := fixture(t)
	useMemoryCache(h)
	h.execute = func(_ context.Context, _ string, _ []string, out io.Writer) execution {
		writeGoEvents(out, "pass")
		return execution{ExitCode: 0}
	}
	call(t, h, "create_test", map[string]any{"path": "pkg/regression_test.go", "content": generatedSource})
	for i := 0; i < 3; i++ {
		call(t, h, "run_generated_test", map[string]any{"test_id": "generated-test-1"})
	}
	replayed := 0
	for _, c := range h.Checks() {
		if c.Kind == model.CheckGeneratedBase && c.Replayed() {
			replayed++
			if c.Status != "PASS" {
				t.Fatalf("replayed baseline %+v", c)
			}
		}
		if c.Kind == model.CheckGeneratedCandidate && c.Cache != nil {
			t.Fatalf("a candidate check carries cache provenance: %+v", c)
		}
	}
	if replayed == 0 {
		t.Fatal("the third baseline run was not replayed")
	}
	for _, dir := range []string{h.base, h.candidate} {
		if _, err := os.Stat(filepath.Join(dir, "pkg", "regression_test.go")); !os.IsNotExist(err) {
			t.Fatal("the generated test was not unstaged")
		}
	}
}

// coverage.ProfilePath captures are keyed separately from results captures,
// because the capture script is part of the key.
func TestCacheKeyCoversTheCaptureScript(t *testing.T) {
	h := fixture(t)
	m := useMemoryCache(h)
	h.executeCapture = func(_ context.Context, _ string, _ []string, _, payload io.Writer) execution {
		fmt.Fprint(payload, coverageFrame("x"))
		return execution{ExitCode: 0}
	}
	countingExec(h, "output\n", 0)
	runBase(h, runOptions{})
	runLocked(h, context.Background(), model.CheckGeneratedBase, h.base, baseCommand, runOptions{capture: ResultsPath})
	runLocked(h, context.Background(), model.CheckGeneratedBase, h.base, baseCommand, runOptions{capture: coverage.ProfilePath})
	if len(m.keys()) != 3 {
		t.Fatalf("capture paths share keys: %v", m.keys())
	}
}
