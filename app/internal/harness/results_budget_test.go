package harness

import (
	"context"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/gvinsot/SwiftProof/app/internal/model"
)

// Results candidate code can write share at most half of ResultsBudget, so they
// never use up what baseline-side captures rely on.
func TestCandidateResultsNeverUseTheBaselineHalf(t *testing.T) {
	h := fixture(t)
	h.mu.Lock()
	candidate := strings.Repeat("c", ResultsBudget/2-10)
	h.checks = []model.Check{{ID: "check-1", Kind: model.CheckGeneratedCandidate, Results: candidate}}
	h.resultsBytes = len(candidate)
	for kind, want := range map[string]int{
		model.CheckGeneratedCandidate:   10,
		model.CheckGeneratedIntent:      10,
		model.CheckFuzzCandidate:        10,
		model.CheckFuzzCandidateConfirm: 10,
		"test":                          10,
		model.CheckGeneratedBase:        ResultsBudget - len(candidate),
		model.CheckGeneratedBaseRepeat:  ResultsBudget - len(candidate),
		model.CheckFuzzBase:             ResultsBudget - len(candidate),
		model.CheckFuzzBaseConfirm:      ResultsBudget - len(candidate),
	} {
		if got := h.resultsRemainingFor(kind); got != want {
			t.Errorf("%s: %d remaining, want %d", kind, got, want)
		}
	}
	// Baseline-side results do not count against the candidate half; the
	// mutation ledger's do.
	h.mutationChecks = []model.Check{{ID: "mutation-check-1", Kind: model.CheckMutant, Results: "m"}}
	h.checks = append(h.checks, model.Check{ID: "check-2", Kind: model.CheckGeneratedBase, Results: strings.Repeat("b", 100)})
	h.resultsBytes += 101
	if got := h.resultsRemainingFor(model.CheckGeneratedCandidate); got != 9 {
		t.Errorf("candidate remaining %d, want 9", got)
	}
	h.mu.Unlock()

	// End to end: an over-share candidate capture is ERROR, and the next
	// baseline capture still records its results.
	h = tsFixture(t)
	report := jestResults("src/cart.test.ts", map[string]string{"applies the discount once": "passed"})
	normalized, err := normalizeJestReport([]byte(report))
	if err != nil {
		t.Fatal(err)
	}
	h.executeCapture = func(_ context.Context, _ string, _ []string, _, payload io.Writer) execution {
		fmt.Fprint(payload, coverageFrame(report))
		return execution{ExitCode: 0}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	filler := strings.Repeat("f", ResultsBudget/2-len(normalized)+1)
	h.checks = []model.Check{{ID: "check-1", Kind: model.CheckGeneratedCandidate, Status: "PASS", Results: filler}}
	h.resultsBytes = len(filler)
	c := h.runWithResultsOptions(context.Background(), model.CheckGeneratedCandidate, h.candidate, h.testCommand("src/cart.test.ts"), runOptions{})
	if c.Status != "ERROR" || c.Results != "" || !strings.Contains(c.Output, resultsOverBudget) {
		t.Fatalf("over-share candidate results: %+v", c)
	}
	c = h.runWithResultsOptions(context.Background(), model.CheckGeneratedBase, h.base, h.testCommand("src/cart.test.ts"), runOptions{})
	if c.Status != "PASS" || c.Results != normalized {
		t.Fatalf("baseline results refused after a candidate overflow: %+v", c)
	}
}
