package harness

import (
	"encoding/json"
	"time"

	"github.com/gvinsot/SwiftProof/app/internal/model"
)

// CacheEntry is what the execution cache persists for one key. It never holds raw output:
// Check.Output is the redacted, recorded log, and Payload is kept only when it is a
// Redact fixed point and was not truncated.
type CacheEntry struct {
	Key           string          // hex sha256; recomputed from Preimage on every Get
	Preimage      json.RawMessage // canonical JSON of the key inputs (§1.11); hashes only, no raw argv
	Status        string          // PASS | FAIL
	ExitCode      int
	Output        string // redacted, as recorded
	Truncated     bool
	DurationMS    int64
	Payload       []byte
	LiveRuns      int  // live executions that agreed on (Status, ExitCode, Truncated)
	Contradicted  bool // a live run disagreed; such an entry is never served
	RecordedAt    time.Time
	RecordedRun   string
	RecordedCheck string
}

// ExecutionCache is the opt-in store of baseline executions. Only the harness
// writes to it, and only for baseline-side kinds (§1.11).
//
// Counting is split by who can observe an event. The harness counts what it
// sees through its own calls: hits (replays it served), misses (a key was
// computed but nothing servable was found), uncacheable runs, successful
// stores, write failures (Put errors), contradictions and the evictions a
// contradiction causes. Stats reports only what the store observes on its
// own: entries it rejected on Get and entries it evicted itself (for example
// by trimming). The execution summary adds the two.
type ExecutionCache interface {
	Get(key string) (CacheEntry, bool) // false on a miss, or on an integrity failure (counted as rejected; entry removed)
	Put(e CacheEntry) error            // atomic replace; errors count as write_failures, never fail the run
	Delete(key string) error
	Stats() model.ExecutionCache // counters for the summary
}
