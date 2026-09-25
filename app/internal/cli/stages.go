package cli

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/gvinsot/SwiftProof/app/internal/config"
	"github.com/gvinsot/SwiftProof/app/internal/model"
)

// Reasons a review executed nothing. They are recorded verbatim as the reason
// of every requested stage that could not run.
const (
	reasonLint              = "lint does not execute sandbox checks"
	reasonNoChangedFiles    = "no changed files"
	reasonExecutionDisabled = "automated execution was explicitly disabled"
	reasonPrepareFailed     = "dependency preparation did not produce an image"
)

// deadlineNote is the Unverified entry of a run whose --deadline cut stages short.
const deadlineNote = "The overall --deadline was reached; later stages did not run or were cut short."

// executionStarted is a test hook called immediately before the first step
// that can start a container (dependency preparation, then the harness). Tests
// replace it to prove that every exit-3 path returns before it.
var executionStarted = func() {}

// stageContext tells the record*Skipped functions why a stage did not run.
type stageContext struct {
	mode     string // "lint" | "review"
	checks   bool   // --checks
	executed bool   // a harness was created
	reason   string // "" when executed; else "no changed files" |
	// "automated execution was explicitly disabled" |
	// "dependency preparation did not produce an image"
}

// noExecutionReason returns "" when a review will create a harness, and the
// reason nothing executes otherwise.
func noExecutionReason(mode string, change model.Change, checks, reviewer bool) string {
	switch {
	case mode != "review":
		return reasonLint
	case len(change.Files) == 0:
		return reasonNoChangedFiles
	case !checks && !reviewer:
		return reasonExecutionDisabled
	}
	return ""
}

// skippedReason is the not_run reason of a requested stage that did not run:
// the stage context's reason, or a generic one when a harness existed but the
// stage never recorded its section (for example after the deadline).
func skippedReason(sc stageContext) string {
	if sc.reason != "" {
		return sc.reason
	}
	return "the stage did not run in this review"
}

// startKey carries the moment a command started, so that --deadline counts from
// the start of the run rather than from the call to workContext.
type startKey struct{}

// withStart records started on ctx for workContext.
func withStart(ctx context.Context, started time.Time) context.Context {
	return context.WithValue(ctx, startKey{}, started)
}

// workContext derives the context of every stage that executes or calls a
// provider (prepare, harness runs, reviewer). With d == 0 it is ctx itself.
// Otherwise its deadline is start + d - 30 s, where start is the time recorded
// by withStart (or now); the 30 s are left for cleanup and report writing,
// which use the parent context.
func workContext(ctx context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	if d == 0 {
		return ctx, func() {}
	}
	start, ok := ctx.Value(startKey{}).(time.Time)
	if !ok {
		start = time.Now()
	}
	return context.WithDeadline(ctx, start.Add(d-deadlineReserve))
}

// deadlineReached reports whether work hit its own deadline while ctx was
// neither cancelled nor expired.
func deadlineReached(ctx, work context.Context) bool {
	return ctx.Err() == nil && errors.Is(work.Err(), context.DeadlineExceeded)
}

// reviewerReserve is the part of the sandbox runtime budget that the
// pre-reviewer v0.4 stages leave to reviewer experiments: half of it when the
// reviewer will run, else nothing (§1.7.1).
func reviewerReserve(cfg config.Config, reviewer bool) time.Duration {
	if !reviewer {
		return 0
	}
	return time.Duration(cfg.Sandbox.MaxRuntimeSeconds) * time.Second / 2
}

// divergenceLine is the stdout line for validated divergences; "" when there
// are none. It states a recorded difference and leaves the verdict to a human.
func divergenceLine(r *model.Report) string {
	switch n := len(r.Divergences); n {
	case 0:
		return ""
	case 1:
		return "1 recorded behavior divergence (baseline and candidate recorded different values; a human decides which is intended)."
	default:
		return fmt.Sprintf("%d recorded behavior divergences (baseline and candidate recorded different values; a human decides which is intended).", n)
	}
}

// stdoutLines returns the per-stage stdout lines in their fixed order (§1.7),
// skipping the empty ones. The Reports line follows them.
func stdoutLines(r *model.Report) []string {
	var out []string
	for _, s := range []string{
		baseTestsLine(r.BaseTests), // F3
		divergenceLine(r),          // F0
		intentLine(r),              // F5
		fuzzLine(r.Fuzz),           // F2
		mutationLine(r.Mutation),   // F4
		impactLine(r.Impact),       // F6a
		executionLine(r.Execution), // F7a
	} {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}
