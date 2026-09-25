package model

// Hypothesis statuses. Only report.Finalize assigns a final status.
const (
	StatusReproduced       = "REPRODUCED"
	StatusDiverged         = "DIVERGED"           // F1/F2
	StatusIntentTestFailed = "INTENT_TEST_FAILED" // F5 (also an evidence status)
	StatusNotReproduced    = "NOT_REPRODUCED"
	StatusDismissed        = "DISMISSED"
	StatusUnverified       = "UNVERIFIED"
)

// Evidence statuses (REPRODUCED, NOT_REPRODUCED, DIVERGED, INTENT_TEST_FAILED
// and UNVERIFIED reuse the constants above).
const (
	StatusObserved          = "OBSERVED"
	StatusNotDiverged       = "NOT_DIVERGED"        // F1/F2; never supports a hypothesis
	StatusFailsOnCandidate  = "FAILS_ON_CANDIDATE"  // F3/F6b
	StatusPassesOnCandidate = "PASSES_ON_CANDIDATE" // F3/F6b
	StatusIntentTestPassed  = "INTENT_TEST_PASSED"  // F5
)

// Evidence kinds. Only harness code creates evidence records.
const (
	EvidenceSourceObservation        = "source_observation"
	EvidenceDifferentialTest         = "differential_test"
	EvidenceDifferentialObservation  = "differential_observation"   // F1
	EvidenceDifferentialFuzz         = "differential_fuzz"          // F2
	EvidenceBaseTestDifferential     = "base_test_differential"     // F3
	EvidenceImpactedTestDifferential = "impacted_test_differential" // F6b
	EvidenceIntentTest               = "intent_test"                // F5
)

// Check kinds. A kind ending in "_base" is a baseline-side run of an experiment
// family and is the only kind the execution cache may serve; a live re-run keeps
// the first-run kind. The only distinct re-run kinds are
// generated_test_base_repeat, fuzz_base_confirm and fuzz_candidate_confirm.
const (
	CheckTest                  = "test"
	CheckTypecheck             = "typecheck"
	CheckBuild                 = "build"
	CheckCoverage              = "coverage"
	CheckExistingTest          = "existing_test"       // reviewer run_test tool (candidate only)
	CheckGeneratedBase         = "generated_test_base" // first run and live confirmation (live: true)
	CheckGeneratedCandidate    = "generated_test_candidate"
	CheckGeneratedBaseRepeat   = "generated_test_base_repeat" // F1, always live, never cached
	CheckGeneratedIntent       = "generated_test_intent"      // F5, candidate only
	CheckFuzzBase              = "fuzz_base"                  // F2
	CheckFuzzCandidate         = "fuzz_candidate"
	CheckFuzzBaseConfirm       = "fuzz_base_confirm" // always live, never cached
	CheckFuzzCandidateConfirm  = "fuzz_candidate_confirm"
	CheckBaseTestBase          = "base_test_base" // F3; first run and live re-run
	CheckBaseTestHybrid        = "base_test_hybrid"
	CheckImpactedTestBase      = "impacted_test_base" // F6b; first run and live re-run
	CheckImpactedTestCandidate = "impacted_test_candidate"
	CheckMutationControl       = "mutation_control" // F4, mutation ledger only
	CheckMutant                = "mutant"           // F4, mutation ledger only
)

// Signal kinds added in v0.4 (kinds stay free strings in the schema).
const (
	SignalTestAssertionRemoved   = "test_assertion_removed"   // F3, medium
	SignalTestCaseRemoved        = "test_case_removed"        // F3, medium
	SignalTestSkipAdded          = "test_skip_added"          // F3, medium
	SignalTestFocusAdded         = "test_focus_added"         // F3, high
	SignalTestExpectationRelaxed = "test_expectation_relaxed" // F3, medium
	SignalSurvivingMutant        = "surviving_mutant"         // F4, medium
	SignalImpactedCaller         = "impacted_caller"          // F6a, low, capped
	SignalAnalysisLimited        = "analysis_limited"         // existing kind; F6a reuses it (medium, symbol "impact_index")
	SignalPrepareInputChanged    = "prepare_input_changed"    // F8, medium
)

// Artifact kinds added in v0.4 (free strings in the schema).
const (
	ArtifactGeneratedTest          = "generated_test" // existing; F1 also retains diverging tests
	ArtifactFuzzHarness            = "fuzz_harness"
	ArtifactFuzzObservations       = "fuzz_observations"
	ArtifactFuzzPayloadRejected    = "fuzz_payload_rejected"
	ArtifactBaseTestHybridManifest = "base_test_hybrid_manifest"
	ArtifactMutationCheckOutput    = "mutation_check_output"
	ArtifactMutantPatch            = "mutant_patch"
	ArtifactIntentTest             = "intent_test"
	ArtifactPrepareOutput          = "prepare_output"
	ArtifactTestResults            = "test_results" // existing
)

// Audit names. Harness stages use the reserved prefix; no tool name contains ':'.
const (
	AuditStagePrefix      = "stage:"
	AuditRejectedToolCall = "rejected_tool_call"
)

// PR-comment markers (F9 writes them; F5's parseIntent strips what they enclose).
const (
	PRCommentBegin = "<!-- swiftproof:pr-comment:begin v1 -->"
	PRCommentEnd   = "<!-- swiftproof:pr-comment:end -->"
)

// Replayed reports whether the check was served from the execution cache rather
// than executed. It is defined here, not in execution.go, so that it stays frozen.
func (c Check) Replayed() bool { return c.Cache != nil && c.Cache.Status == CacheHit }
