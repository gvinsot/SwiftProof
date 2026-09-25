package model

import "time"

// Execution-cache statuses and scope.
const (
	CacheHit           = "hit"
	CacheStored        = "stored"
	CacheEnabled       = "enabled"
	CacheDisabled      = "disabled"
	CacheScopeBaseline = "baseline_only"
)

// CheckCache is present only on a base-side check that was stored in or
// replayed from the opt-in execution cache. A hit is not a fresh execution.
type CheckCache struct {
	Status             string    `json:"status"`
	Key                string    `json:"key"`
	RecordedAt         time.Time `json:"recorded_at"`
	RecordedRun        string    `json:"recorded_run"`
	RecordedCheck      string    `json:"recorded_check"`
	RecordedDurationMS int64     `json:"recorded_duration_ms"`
	LiveRuns           int       `json:"live_runs"`
}
type ExecutionCache struct {
	Status        string `json:"status"`
	Reason        string `json:"reason,omitempty"`
	Scope         string `json:"scope"`
	ImageID       string `json:"image_id,omitempty"`
	PolicySHA256  string `json:"policy_sha256,omitempty"`
	Hits          int    `json:"hits"`
	Stored        int    `json:"stored"`
	Misses        int    `json:"misses"`
	Uncacheable   int    `json:"uncacheable"`
	Rejected      int    `json:"rejected"`
	WriteFailures int    `json:"write_failures"`
	Evicted       int    `json:"evicted"`
	Contradicted  int    `json:"contradicted"`
	Note          string `json:"note"`
}
type ExecutionParallelism struct {
	Requested int    `json:"requested"`
	Effective int    `json:"effective"`
	Note      string `json:"note"`
}
type ExecutionBudget struct {
	MaxRuntimeMS      int64 `json:"max_runtime_ms"`
	SpentMS           int64 `json:"spent_ms"`
	ReviewerReserveMS int64 `json:"reviewer_reserve_ms"`
	DeadlineReached   bool  `json:"deadline_reached"`
}

// Execution summarizes the cache, parallelism and budget of a run in which a
// harness was created. (Check.Replayed is in status.go.)
type Execution struct {
	Cache        ExecutionCache       `json:"cache"`
	Parallelism  ExecutionParallelism `json:"parallelism"`
	Budget       ExecutionBudget      `json:"budget"`
	ReplayBacked []string             `json:"replay_backed"` // evidence IDs; set by finalizeExecution
}
