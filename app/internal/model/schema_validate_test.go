package model

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// validator is a small, stdlib-only JSON Schema evaluator for the keyword
// subset that TestSchemaStructure allows. It exists so the conditional rules of
// the report schema are exercised by `go test`; it is not a general validator.
type validator struct {
	s        *schemaDoc
	patterns map[string]*regexp.Regexp
}

func newValidator(s *schemaDoc) *validator {
	return &validator{s: s, patterns: map[string]*regexp.Regexp{}}
}

func (v *validator) validateDocument(inst any) []string {
	return v.validate(v.s.root, inst, "")
}

// validate returns one message per violated constraint; an empty result means
// the instance is valid against node.
func (v *validator) validate(node map[string]any, inst any, at string) []string {
	var errs []string
	fail := func(format string, args ...any) {
		errs = append(errs, (at+": ")+fmt.Sprintf(format, args...))
	}
	if ref, ok := node["$ref"]; ok {
		target, err := v.s.resolve(map[string]any{"$ref": ref})
		if err != nil {
			fail("%v", err)
			return errs
		}
		errs = append(errs, v.validate(target, inst, at)...)
	}
	for key, raw := range node {
		switch key {
		case "$ref", "$schema", "$id", "$defs", "title", "description", "then", "else", "additionalProperties":
			// $ref is handled above; then/else with if; additionalProperties with properties.
		case "type":
			if !hasType(inst, raw.(string)) {
				fail("type %s expected, got %s", raw, describe(inst))
			}
		case "enum":
			found := false
			for _, candidate := range raw.([]any) {
				if jsonEqual(candidate, inst) {
					found = true
					break
				}
			}
			if !found {
				fail("value %s is not in enum %v", describe(inst), raw)
			}
		case "const":
			if !jsonEqual(raw, inst) {
				fail("value %s is not the constant %v", describe(inst), raw)
			}
		case "format":
			if str, ok := inst.(string); ok && raw == "date-time" {
				if _, err := time.Parse(time.RFC3339Nano, str); err != nil {
					fail("%q is not a date-time", str)
				}
			}
		case "properties":
			obj, ok := inst.(map[string]any)
			if !ok {
				continue
			}
			props := raw.(map[string]any)
			for name, value := range obj {
				if sub, ok := props[name].(map[string]any); ok {
					errs = append(errs, v.validate(sub, value, at+"/"+name)...)
				} else if node["additionalProperties"] == false {
					fail("property %q is not allowed", name)
				}
			}
		case "required":
			obj, ok := inst.(map[string]any)
			if !ok {
				continue
			}
			for _, name := range raw.([]any) {
				if _, ok := obj[name.(string)]; !ok {
					fail("required property %q is missing", name)
				}
			}
		case "items":
			arr, ok := inst.([]any)
			if !ok {
				continue
			}
			for i, item := range arr {
				errs = append(errs, v.validate(raw.(map[string]any), item, fmt.Sprintf("%s/%d", at, i))...)
			}
		case "minItems", "maxItems":
			arr, ok := inst.([]any)
			if !ok {
				continue
			}
			limit := mustInt(raw)
			if key == "minItems" && len(arr) < limit || key == "maxItems" && len(arr) > limit {
				fail("%d items violates %s %d", len(arr), key, limit)
			}
		case "uniqueItems":
			arr, ok := inst.([]any)
			if !ok || raw != true {
				continue
			}
			for i := range arr {
				for j := i + 1; j < len(arr); j++ {
					if jsonEqual(arr[i], arr[j]) {
						fail("items %d and %d are equal", i, j)
					}
				}
			}
		case "minLength", "maxLength":
			str, ok := inst.(string)
			if !ok {
				continue
			}
			n, limit := utf8.RuneCountInString(str), mustInt(raw)
			if key == "minLength" && n < limit || key == "maxLength" && n > limit {
				fail("length %d violates %s %d", n, key, limit)
			}
		case "pattern":
			str, ok := inst.(string)
			if !ok {
				continue
			}
			re, ok := v.patterns[raw.(string)]
			if !ok {
				re = regexp.MustCompile(raw.(string))
				v.patterns[raw.(string)] = re
			}
			if !re.MatchString(str) {
				fail("%q does not match %s", str, raw)
			}
		case "minimum", "maximum":
			num, ok := inst.(json.Number)
			if !ok {
				continue
			}
			got, _ := new(big.Rat).SetString(num.String())
			limit, _ := new(big.Rat).SetString(raw.(json.Number).String())
			if key == "minimum" && got.Cmp(limit) < 0 || key == "maximum" && got.Cmp(limit) > 0 {
				fail("%s violates %s %s", num, key, raw)
			}
		case "allOf":
			for _, member := range raw.([]any) {
				errs = append(errs, v.validate(member.(map[string]any), inst, at)...)
			}
		case "not":
			if len(v.validate(raw.(map[string]any), inst, at)) == 0 {
				fail("instance matches a forbidden schema")
			}
		case "if":
			branch := "else"
			if len(v.validate(raw.(map[string]any), inst, at)) == 0 {
				branch = "then"
			}
			if sub, ok := node[branch].(map[string]any); ok {
				errs = append(errs, v.validate(sub, inst, at)...)
			}
		default:
			fail("unsupported schema keyword %q", key)
		}
	}
	return errs
}

func mustInt(raw any) int {
	n, err := strconv.Atoi(raw.(json.Number).String())
	if err != nil {
		panic(err)
	}
	return n
}

func hasType(inst any, typ string) bool {
	switch typ {
	case "object":
		_, ok := inst.(map[string]any)
		return ok
	case "array":
		_, ok := inst.([]any)
		return ok
	case "string":
		_, ok := inst.(string)
		return ok
	case "boolean":
		_, ok := inst.(bool)
		return ok
	case "null":
		return inst == nil
	case "number":
		_, ok := inst.(json.Number)
		return ok
	case "integer":
		num, ok := inst.(json.Number)
		if !ok {
			return false
		}
		r, ok := new(big.Rat).SetString(num.String())
		return ok && r.IsInt()
	}
	return false
}

func jsonEqual(a, b any) bool {
	na, aNum := a.(json.Number)
	nb, bNum := b.(json.Number)
	if aNum || bNum {
		if !aNum || !bNum {
			return false
		}
		ra, okA := new(big.Rat).SetString(na.String())
		rb, okB := new(big.Rat).SetString(nb.String())
		return okA && okB && ra.Cmp(rb) == 0
	}
	switch x := a.(type) {
	case map[string]any:
		y, ok := b.(map[string]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for k, xv := range x {
			yv, ok := y[k]
			if !ok || !jsonEqual(xv, yv) {
				return false
			}
		}
		return true
	case []any:
		y, ok := b.([]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for i := range x {
			if !jsonEqual(x[i], y[i]) {
				return false
			}
		}
		return true
	}
	return reflect.DeepEqual(a, b)
}

func describe(inst any) string {
	data, _ := json.Marshal(inst)
	if len(data) > 80 {
		return string(data[:80]) + "..."
	}
	return string(data)
}

func decodeJSON(t *testing.T, data []byte) any {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

func toJSONValue(t *testing.T, v any) any {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return decodeJSON(t, data)
}

// populatedReport returns a report that sets the fields of every section with
// values a real run could record, including every v0.4 evidence kind. Owners
// who add a non-omitempty field whose zero value the schema rejects must make
// this fixture set it (through the integrator, §0.6) or accept the zero value.
func populatedReport() Report {
	at := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	sha := strings.Repeat("a", 64)
	img := "sha256:" + strings.Repeat("b", 64)
	base, head := strings.Repeat("c", 40), strings.Repeat("d", 40)
	stored := &CheckCache{Status: CacheStored, Key: sha, RecordedAt: at, RecordedRun: "2026-09-25T11:00:00Z", RecordedCheck: "check-2", RecordedDurationMS: 12, LiveRuns: 1}
	hit := &CheckCache{Status: CacheHit, Key: strings.Repeat("e", 64), RecordedAt: at, RecordedRun: "2026-09-24T11:00:00Z", RecordedCheck: "check-5", RecordedDurationMS: 30, LiveRuns: 2}
	check := func(id, kind, status string, exit int, cache *CheckCache) Check {
		return Check{ID: id, Kind: kind, Status: status, Command: []string{"go", "test", "-json", "./calc"}, ExitCode: exit, DurationMS: 25, Output: "{\"Action\":\"pass\"}", Truncated: false, Cache: cache}
	}
	reproduced := Hypothesis{ID: "hypothesis-1", Title: "Discount rounds up", Severity: "high", Status: StatusReproduced, Rationale: "The generated test fails on the candidate only.", EvidenceIDs: []string{"evidence-2"}, Path: "calc/calc.go", Line: 3}
	intentFailure := Hypothesis{ID: "hypothesis-3", Title: "AC-1 test failed", Severity: "medium", Status: StatusIntentTestFailed, Rationale: "r", EvidenceIDs: []string{"evidence-7"}, Path: "calc/calc.go", Line: 3, CriterionID: "AC-1"}
	return Report{
		Version:        1,
		ToolVersion:    "v0.4.0-test",
		GeneratedAt:    at,
		Intent:         "Discounts round down.\nAC-1: Discount(5,33) returns 3.",
		IntentSHA256:   sha,
		IntentCriteria: []IntentCriterion{{ID: "AC-1", Text: "Discount(5,33) returns 3.", Line: 2}},
		Change: Change{
			BaseRef: "main", HeadRef: "HEAD", BaseCommit: base, HeadCommit: head, BaseRefCommit: base,
			Files: []ChangedFile{{
				Path: "calc/calc.go", OldPath: "calc/old.go", Status: "R", Binary: false, Additions: 1, Deletions: 1,
				Hunks: []Hunk{{OldStart: 3, OldLines: 2, NewStart: 3, NewLines: 2, Lines: []DiffLine{
					{Kind: "delete", OldLine: 3, Content: "return p * d / 100"},
					{Kind: "add", NewLine: 3, Content: "return (p*d + 99) / 100"},
					{Kind: "context", OldLine: 4, NewLine: 4, Content: "}"},
				}}},
			}},
			Additions: 1, Deletions: 1,
		},
		Policy: Policy{Source: PolicyBaseRef, Commit: base, Path: ".swiftproof.json"},
		Prepare: &Prepare{
			Status: PrepareBuilt, Reason: "built from the base commit", SourceCommit: base, Command: []string{"go", "mod", "download"},
			User: "sandbox", Network: false, Key: sha, BaseImage: "golang:1.26-bookworm", BaseImageID: img, ImageID: "sha256:" + strings.Repeat("f", 64),
			AddedBytes: 4096, Inputs: []PreparedInput{{Path: "go.sum", SHA256: sha, Size: 120}}, LogSHA256: sha, DurationMS: 900, Note: PrepareNote,
		},
		Signals: []Signal{{ID: "signal-1", Kind: SignalSurvivingMutant, Path: "calc/calc.go", Line: 3, EndLine: 3, Side: "new", Symbol: "Discount", Severity: "medium", Summary: "A mutant of an added line survived", Evidence: "mutant-1"}},
		Checks: []Check{
			check("check-1", CheckTest, "PASS", 0, nil),
			check("check-2", CheckGeneratedBase, "PASS", 0, stored),
			check("check-3", CheckGeneratedCandidate, "FAIL", 1, nil),
			check("check-4", CheckGeneratedBaseRepeat, "PASS", 0, nil),
			check("check-5", CheckFuzzBase, "PASS", 0, hit),
			check("check-6", CheckFuzzCandidate, "PASS", 0, nil),
			check("check-7", CheckFuzzBaseConfirm, "PASS", 0, nil),
			check("check-8", CheckFuzzCandidateConfirm, "PASS", 0, nil),
			check("check-9", CheckBaseTestBase, "PASS", 0, nil),
			check("check-10", CheckBaseTestHybrid, "FAIL", 1, nil),
			check("check-11", CheckImpactedTestBase, "PASS", 0, nil),
			check("check-12", CheckImpactedTestCandidate, "PASS", 0, nil),
			check("check-13", CheckGeneratedIntent, "FAIL", 1, nil),
			{ID: "check-14", Kind: CheckCoverage, Status: "SKIPPED", ExitCode: -1, Output: "Sandbox runtime budget exhausted.", Results: "{\"numTotalTests\":1}"},
		},
		Hypotheses: []Hypothesis{
			reproduced,
			{ID: "hypothesis-2", Title: "Discount output changed", Severity: "medium", Status: StatusDiverged, Rationale: "r", EvidenceIDs: []string{"evidence-3"}, Path: "calc/calc.go", Line: 3, CriterionID: "AC-1", IntentJudgment: JudgmentUnexpectedChange},
			intentFailure,
			{ID: "hypothesis-4", Title: "Unused import", Severity: "low", Status: StatusDismissed, Rationale: "The import is used by the test build.", EvidenceIDs: []string{"evidence-1"}},
			{ID: "hypothesis-5", Title: "Unsupported claim", Severity: "low", Status: StatusUnverified, Rationale: "r", EvidenceIDs: []string{}},
		},
		Evidence: []Evidence{
			{ID: "evidence-1", Kind: EvidenceSourceObservation, Description: "d", Path: "calc/calc.go", Output: "3: return (p*d + 99) / 100", Status: StatusObserved, TestNames: []string{}},
			{ID: "evidence-2", Kind: EvidenceDifferentialTest, Description: "d", Path: "calc/discount_swiftproof_test.go", CheckID: "check-3", BaseCheckID: "check-2", Status: StatusReproduced, Runner: "go_test_json", TestNames: []string{"TestDiscountRounding"}},
			{ID: "evidence-3", Kind: EvidenceDifferentialObservation, Description: "d", Path: "calc/discount_swiftproof_test.go", CheckID: "check-3", BaseCheckID: "check-2", RepeatCheckID: "check-4", Status: StatusDiverged, Runner: "go_test_json", TestNames: []string{"TestDiscountRounding"}},
			{ID: "evidence-4", Kind: EvidenceDifferentialFuzz, Description: "d", Path: "calc/swiftproof_fuzz_x1_test.go", CheckID: "check-6", BaseCheckID: "check-5", Status: StatusNotDiverged, Runner: "go_test_json", TestNames: []string{"TestSwiftProofFuzzX1"}},
			{ID: "evidence-5", Kind: EvidenceBaseTestDifferential, Description: "d", Path: "calc/calc_test.go", CheckID: "check-10", BaseCheckID: "check-9", Status: StatusFailsOnCandidate, Runner: "go_test_json", TestNames: []string{"TestDiscount"}},
			{ID: "evidence-6", Kind: EvidenceImpactedTestDifferential, Description: "d", Path: "shop/cart_test.go", CheckID: "check-12", BaseCheckID: "check-11", Status: StatusPassesOnCandidate, Runner: "go_test_json", TestNames: []string{"TestTotal"}},
			{ID: "evidence-7", Kind: EvidenceIntentTest, Description: "d", Path: "calc/intent_ac1_test.go", CheckID: "check-13", CriterionID: "AC-1", ReferencedSymbols: []string{"Discount", "$helper"}, Status: StatusIntentTestFailed, Runner: "go_test_json", TestNames: []string{"TestAC1"}},
			{ID: "evidence-8", Kind: EvidenceDifferentialFuzz, Description: "d", Path: "calc/swiftproof_fuzz_x1_test.go", CheckID: "check-6", BaseCheckID: "check-5", Status: StatusDiverged, Runner: "go_test_json", TestNames: []string{"TestSwiftProofFuzzX1"}},
		},
		ReproducedIssues: []Hypothesis{reproduced},
		BaseTests: &BaseTests{Status: BaseTestsRan, Reason: "r", Note: BaseTestsNote, Tests: []BaseTest{{
			Name: "TestDiscount", Path: "calc/calc_test.go", Line: 5, EndLine: 9, CandidatePath: "calc/calc_test.go", CandidateLine: 5, CandidateEndLine: 10,
			Change: BaseTestModified, Status: StatusFailsOnCandidate, EvidenceID: "evidence-5", Reason: "r",
		}}},
		Divergences: []Divergence{
			{
				EvidenceID: "evidence-3", Kind: EvidenceDifferentialObservation, Path: "calc/calc.go", Line: 3, Symbol: "Discount", AnchorSource: "hypothesis",
				TestPath: "calc/discount_swiftproof_test.go", TestNames: []string{"TestDiscountRounding"}, CheckIDs: []string{"check-2", "check-3", "check-4"},
				HypothesisIDs: []string{"hypothesis-2"}, Note: DivergenceNote,
				Observations: []Observation{{Test: "TestDiscountRounding", Key: "Discount(5,33)", Status: ObservationDiverged, Base: "3", Candidate: "4", BaseRecorded: true, CandidateRecorded: true, Truncated: true, Reason: "r"}},
			},
			{
				EvidenceID: "evidence-8", Kind: EvidenceDifferentialFuzz, Path: "calc/calc.go", Line: 3, Symbol: "Percent", AnchorSource: "changed_function",
				TestPath: "calc/swiftproof_fuzz_x1_test.go", TestNames: []string{"TestSwiftProofFuzzX1"}, CheckIDs: []string{"check-5", "check-6", "check-7", "check-8"},
				HypothesisIDs: []string{}, Note: DivergenceNote,
				Observations: []Observation{{Test: "TestSwiftProofFuzzX1", Key: "Percent(7, 3)", Status: ObservationDiverged, Base: "0", Candidate: "1", BaseRecorded: true, CandidateRecorded: true}},
			},
		},
		IntentTestFailures: []Hypothesis{intentFailure},
		Unverified:         []string{"Mutation analysis stopped at max_mutants."},
		ReviewTargets:      []ReviewTarget{{Path: "calc/calc.go", StartLine: 3, EndLine: 3, Side: "new", Severity: "high", Reasons: []string{"reproduced issue"}, SignalIDs: []string{"signal-1"}}},
		ReviewSurface:      ReviewSurface{ChangedLines: 2, FocusedLines: 1, Note: "n"},
		Coverage: Coverage{
			Status: "measured", Reason: "r", CheckID: "check-14", ProfileSHA256: sha, Command: []string{"go", "test", "-coverprofile=/tmp/c.out", "./..."},
			AddedLines: 1, ExecutedLines: 1, RemovedLines: 1, Note: "n",
			Files: []CoverageFile{{Path: "calc/calc.go", Status: "measured", AddedLines: 1, ExecutedLines: 1}},
		},
		Mutation: &Mutation{
			Status: MutationIncomplete, Reason: "max_mutants dropped candidates", Command: []string{"go", "test", "-json", "{package}"},
			Limits: MutationLimits{MaxMutants: 10, TimeoutSeconds: 60, MaxRuntimeSeconds: 300},
			Files:  []MutationFile{{Path: "calc/calc.go", Status: MutationFileEligible, Reason: "r", AddedLines: 1, MutatedLines: 1}},
			Mutants: []Mutant{
				{ID: "mutant-1", Path: "calc/calc.go", Line: 3, Package: "example.com/calc", Operator: "arith", Original: "p*d + 99", Mutated: "p*d - 99", Status: MutantSurvived, CheckID: "mutation-check-2", ControlCheckID: "mutation-check-1", PatchSHA256: sha, TestsRun: 2, Reason: "r"},
				{ID: "mutant-2", Path: "calc/calc.go", Line: 3, Package: "example.com/calc", Operator: "arith", Original: "/ 100", Mutated: "* 100", Status: MutantKilled, CheckID: "mutation-check-3", ControlCheckID: "mutation-check-1", FailedTests: []string{"TestDiscount"}},
				{ID: "mutant-3", Path: "calc/calc.go", Line: 3, Package: "example.com/calc", Operator: "const", Original: "99", Mutated: "100", Status: MutantNotRun},
			},
			Generated: 4, Dropped: 1, Killed: 1, Survived: 1, NotRun: 1,
			Checks: []Check{
				check("mutation-check-1", CheckMutationControl, "PASS", 0, nil),
				check("mutation-check-2", CheckMutant, "PASS", 0, nil),
				check("mutation-check-3", CheckMutant, "FAIL", 1, nil),
			},
			Note: MutationNote,
		},
		Fuzz: &FuzzReport{
			Status: FuzzRan, Reason: "r", SeedScheme: FuzzSeedScheme,
			Limits: FuzzLimits{MaxFunctions: 8, MaxPackages: 4, MaxInputs: 64, CallTimeoutMS: 1000, MaxRuntimeSeconds: 240},
			Functions: []FuzzFunction{{
				Path: "calc/calc.go", Line: 3, EndLine: 5, Symbol: "Percent", Signature: "func(int, int) int", TestName: "TestSwiftProofFuzzX1",
				Outcome: FuzzDiverged, Reason: "r", EvidenceID: "evidence-8",
				Checks:         &FuzzChecks{Base: "check-5", Candidate: "check-6", BaseConfirm: "check-7", CandidateConfirm: "check-8"},
				Counterexample: &FuzzCounterexample{Index: 7, Input: "Percent(7, 3)", Base: "0", Candidate: "1"},
				ResultsSHA256:  sha, Inputs: 64, Compared: 64, Diverged: 3, Unstable: 0, Unconfirmed: 0, NotRecorded: 0,
			}},
			Skipped:      []FuzzSkip{{Path: "web/cart.ts", Line: 0, Symbol: "total", Reason: "TS/JS differential fuzzing is not implemented in v0.4"}},
			SkippedTotal: 1,
			Note:         FuzzNote,
		},
		Impact: &Impact{
			Status: ImpactIndexed, Reason: "r", IndexedFiles: 12,
			ChangedFunctions: []ImpactFunction{{
				Path: "calc/calc.go", Line: 3, EndLine: 5, Symbol: "Discount", Change: ChangeBodyChanged,
				Callers:      []ImpactCaller{{Path: "shop/cart.go", Line: 7, Symbol: "Total", Depth: 1, Resolution: ResolutionStatic}},
				CallersTotal: 1,
				Tests:        []ImpactTest{{Name: "TestTotal", Path: "shop/cart_test.go", Line: 4, Package: "example.com/shop", Depth: 2, Resolution: ResolutionInterface, EvidenceID: "evidence-6", Status: StatusPassesOnCandidate, Reason: "r"}},
			}},
			TestsStatus: ImpactTestsRan, TestsReason: "r", Note: ImpactNote,
		},
		Execution: &Execution{
			Cache: ExecutionCache{
				Status: CacheEnabled, Reason: "r", Scope: CacheScopeBaseline, ImageID: img, PolicySHA256: sha,
				Hits: 1, Stored: 1, Misses: 2, Uncacheable: 1, Rejected: 0, WriteFailures: 0, Evicted: 0, Contradicted: 0, Note: "n",
			},
			Parallelism:  ExecutionParallelism{Requested: 2, Effective: 2, Note: "n"},
			Budget:       ExecutionBudget{MaxRuntimeMS: 600000, SpentMS: 1200, ReviewerReserveMS: 300000, DeadlineReached: false},
			ReplayBacked: []string{"evidence-4"},
		},
		Artifacts: []Artifact{{Path: "artifacts/check-1.log", Kind: "check_output", SHA256: sha}, {Path: "artifacts/mutant-1.patch", Kind: ArtifactMutantPatch, SHA256: sha}},
		Audit:     []AuditEvent{{Time: at, Tool: AuditStagePrefix + "run_fuzz", Arguments: "{}", Status: "OK", DurationMS: 1}, {Time: at, Tool: AuditRejectedToolCall, Arguments: "{\"requested_tool\":\"shell\"}", Status: "ERROR"}},
		ExitCode:  1,
	}
}

// jsonPath addresses a decoded JSON value with "/"-separated keys and indexes.
func jsonPath(doc any, path string) (parent any, last string) {
	parts := strings.Split(path, "/")
	cur := doc
	for _, p := range parts[:len(parts)-1] {
		switch c := cur.(type) {
		case map[string]any:
			cur = c[p]
		case []any:
			i, err := strconv.Atoi(p)
			if err != nil || i < 0 || i >= len(c) {
				panic("bad index " + p + " in " + path)
			}
			cur = c[i]
		default:
			panic("cannot descend into " + p + " of " + path)
		}
	}
	return cur, parts[len(parts)-1]
}

// deleteKey is the sentinel value that removes a key instead of setting it.
type deleteKey struct{}

func setJSON(t *testing.T, doc any, path string, value any) {
	t.Helper()
	parent, last := jsonPath(doc, path)
	switch p := parent.(type) {
	case map[string]any:
		if _, ok := value.(deleteKey); ok {
			if _, ok := p[last]; !ok {
				t.Fatalf("%s: nothing to delete; the fixture changed", path)
			}
			delete(p, last)
			return
		}
		p[last] = toJSONValue(t, value)
	case []any:
		i, err := strconv.Atoi(last)
		if err != nil || i < 0 || i >= len(p) {
			t.Fatalf("%s: bad index", path)
		}
		p[i] = toJSONValue(t, value)
	default:
		t.Fatalf("%s: parent is not a container", path)
	}
}

func getJSON(doc any, path string) any {
	parent, last := jsonPath(doc, path)
	switch p := parent.(type) {
	case map[string]any:
		return p[last]
	case []any:
		i, _ := strconv.Atoi(last)
		return p[i]
	}
	return nil
}

type edit struct {
	path  string
	value any
}

// schemaCases are edits of the populated report. Valid cases must still
// validate; invalid cases must be rejected by the schema.
func schemaCases(t *testing.T) (valid, invalid map[string][]edit) {
	manyCriteria := make([]IntentCriterion, 101)
	for i := range manyCriteria {
		manyCriteria[i] = IntentCriterion{ID: fmt.Sprintf("AC-%d", i+1), Text: "t", Line: i + 1}
	}
	manyCallers := make([]ImpactCaller, 11)
	for i := range manyCallers {
		manyCallers[i] = ImpactCaller{Path: "shop/cart.go", Line: i + 1, Symbol: "Total", Depth: 1, Resolution: ResolutionStatic}
	}
	manySkips := make([]FuzzSkip, 201)
	for i := range manySkips {
		manySkips[i] = FuzzSkip{Path: "web/cart.ts", Line: i, Symbol: "f", Reason: "r"}
	}
	d := deleteKey{}
	valid = map[string][]edit{
		"populated":                             nil,
		"impacted test not run":                 {{"impact/changed_functions/0/tests/0/status", d}, {"impact/changed_functions/0/tests/0/evidence_id", d}},
		"base test unverified without evidence": {{"base_tests/tests/0/status", StatusUnverified}, {"base_tests/tests/0/evidence_id", d}},
		"fuzz stub not_run": {{"fuzz", FuzzReport{Status: FuzzNotRun, Reason: "differential fuzzing is not implemented in this build", SeedScheme: FuzzSeedScheme,
			Limits: FuzzLimits{MaxFunctions: 8, MaxPackages: 4, MaxInputs: 64, CallTimeoutMS: 1000, MaxRuntimeSeconds: 240}, Functions: []FuzzFunction{}, Skipped: []FuzzSkip{}, Note: FuzzNote}}},
		"mutation stub not_run": {{"mutation", Mutation{Status: MutationNotRun, Reason: "not implemented in this build", Command: []string{"go", "test", "-json", "{package}"},
			Limits: MutationLimits{MaxMutants: 10, TimeoutSeconds: 60, MaxRuntimeSeconds: 300}, Files: []MutationFile{}, Mutants: []Mutant{}, Checks: []Check{}, Note: MutationNote}}},
		"impact stub unavailable": {{"impact", Impact{Status: ImpactUnavailable, Reason: "the symbol index is not implemented in this build", ChangedFunctions: []ImpactFunction{}, Note: ImpactNote}}},
		"prepare stub failed": {{"prepare", Prepare{Status: PrepareFailed, Reason: "dependency preparation is not implemented in this build", SourceCommit: strings.Repeat("c", 40),
			Command: []string{"npm", "ci"}, User: "sandbox", BaseImage: "node:22", Inputs: []PreparedInput{}, Note: PrepareNote}}},
		"execution without cache": {{"execution", Execution{Cache: ExecutionCache{Status: CacheDisabled, Reason: "no --cache-dir", Scope: CacheScopeBaseline, Note: "n"},
			Parallelism: ExecutionParallelism{Requested: 1, Effective: 1, Note: "n"}, ReplayBacked: []string{}}}},
		"unverified intent evidence":            {{"evidence/6/status", StatusUnverified}, {"evidence/6/referenced_symbols", d}},
		"unverified observation without repeat": {{"evidence/2/status", StatusUnverified}, {"evidence/2/repeat_check_id", d}},
		"unanchored divergence":                 {{"divergences/0/path", d}, {"divergences/0/line", d}, {"divergences/0/symbol", d}, {"divergences/0/anchor_source", d}},
		"sha-256 object format commit":          {{"prepare/source_commit", strings.Repeat("0", 64)}},
		"legacy v0.2 report": {
			{"intent_sha256", d}, {"intent_criteria", d}, {"policy", d}, {"prepare", d}, {"base_tests", d}, {"divergences", d},
			{"intent_test_failures", d}, {"coverage", d}, {"mutation", d}, {"fuzz", d}, {"impact", d}, {"execution", d},
			{"change/base_ref_commit", d}, {"checks/1/cache", d}, {"checks/4/cache", d},
			{"evidence", []Evidence{populatedReport().Evidence[0], populatedReport().Evidence[1]}},
			{"hypotheses", []Hypothesis{populatedReport().Hypotheses[0], populatedReport().Hypotheses[3]}},
		},
	}
	invalid = map[string][]edit{
		"observation DIVERGED without repeat check":     {{"evidence/2/repeat_check_id", d}},
		"observation evidence without runner":           {{"evidence/2/status", StatusUnverified}, {"evidence/2/runner", d}},
		"observation evidence status FAILS":             {{"evidence/2/status", StatusFailsOnCandidate}},
		"fuzz evidence with two test names":             {{"evidence/3/test_names", []string{"A", "B"}}},
		"fuzz evidence with the jest runner":            {{"evidence/3/runner", "jest_json"}},
		"fuzz evidence without base check":              {{"evidence/3/base_check_id", d}},
		"base test evidence status NOT_DIVERGED":        {{"evidence/4/status", StatusNotDiverged}},
		"base test evidence with two test names":        {{"evidence/4/test_names", []string{"A", "B"}}},
		"impacted test evidence without base check":     {{"evidence/5/base_check_id", d}},
		"impacted test evidence status REPRODUCED":      {{"evidence/5/status", StatusReproduced}},
		"intent evidence with a base check":             {{"evidence/6/base_check_id", "check-2"}},
		"intent failure without referenced symbols":     {{"evidence/6/referenced_symbols", d}},
		"intent failure with empty referenced symbols":  {{"evidence/6/referenced_symbols", []string{}}},
		"intent evidence symbol not an identifier":      {{"evidence/6/referenced_symbols", []string{"1abc"}}},
		"intent evidence without criterion":             {{"evidence/6/criterion_id", d}},
		"intent evidence criterion AC-0":                {{"evidence/6/criterion_id", "AC-0"}},
		"intent evidence status DIVERGED":               {{"evidence/6/status", StatusDiverged}},
		"differential test status NOT_DIVERGED":         {{"evidence/1/status", StatusNotDiverged}},
		"reproduced evidence without runner":            {{"evidence/1/runner", d}},
		"positive evidence without test names":          {{"evidence/1/test_names", []string{}}},
		"unknown evidence kind":                         {{"evidence/0/kind", "model_claim"}},
		"unknown evidence status":                       {{"evidence/0/status", "CONTRADICTED"}},
		"cache on a candidate check":                    {{"checks/2/cache", getJSONValue(t, "checks/1/cache")}},
		"cache with zero live runs":                     {{"checks/1/cache/live_runs", 0}},
		"cache with an invalid key":                     {{"checks/1/cache/key", "abc"}},
		"cache with an unknown status":                  {{"checks/1/cache/status", "miss"}},
		"judgment on a reproduced hypothesis":           {{"hypotheses/0/criterion_id", "AC-1"}, {"hypotheses/0/intent_judgment", JudgmentExpectedChange}},
		"judgment without criterion":                    {{"hypotheses/1/criterion_id", d}},
		"unknown judgment":                              {{"hypotheses/1/intent_judgment", "correct"}},
		"intent failure hypothesis without criterion":   {{"hypotheses/2/criterion_id", d}},
		"diverged hypothesis without evidence":          {{"hypotheses/1/evidence_ids", []string{}}},
		"unknown hypothesis status":                     {{"hypotheses/4/status", "CONTRADICTS_INTENT"}},
		"intent failure list with DIVERGED status":      {{"intent_test_failures/0/status", StatusDiverged}},
		"intent failure list without criterion":         {{"intent_test_failures/0/criterion_id", d}},
		"reproduced list with DIVERGED status":          {{"reproduced_issues/0/status", StatusDiverged}},
		"fuzz divergence with three checks":             {{"divergences/1/check_ids", []string{"check-5", "check-6", "check-7"}}},
		"observation divergence with two checks":        {{"divergences/0/check_ids", []string{"check-2", "check-3"}}},
		"divergence row not DIVERGED":                   {{"divergences/0/observations/0/status", ObservationEqual}},
		"divergence without rows":                       {{"divergences/0/observations", []Observation{}}},
		"divergence anchored without path":              {{"divergences/0/path", d}},
		"divergence without test names":                 {{"divergences/0/test_names", []string{}}},
		"divergence of an unknown kind":                 {{"divergences/0/kind", EvidenceDifferentialTest}},
		"fuzz function diverged without counterexample": {{"fuzz/functions/0/counterexample", d}},
		"fuzz function diverged without confirmation":   {{"fuzz/functions/0/checks/base_confirm", d}},
		"fuzz function diverged without evidence":       {{"fuzz/functions/0/evidence_id", d}},
		"fuzz function unknown outcome":                 {{"fuzz/functions/0/outcome", "equivalent"}},
		"fuzz limit zero":                               {{"fuzz/limits/max_inputs", 0}},
		"fuzz seed scheme":                              {{"fuzz/seed_scheme", "swiftproof-fuzz/v2"}},
		"fuzz skipped over 200":                         {{"fuzz/skipped", manySkips}},
		"fuzz unknown status":                           {{"fuzz/status", "complete"}},
		"fuzz unknown property":                         {{"fuzz/score", 1}},
		"mutant survived without tests run":             {{"mutation/mutants/0/tests_run", d}},
		"mutant survived without patch hash":            {{"mutation/mutants/0/patch_sha256", d}},
		"mutant killed without failed tests":            {{"mutation/mutants/1/failed_tests", d}},
		"mutant check outside the mutation ledger":      {{"mutation/mutants/0/check_id", "check-3"}},
		"mutant id":                             {{"mutation/mutants/0/id", "m1"}},
		"mutation unknown status":               {{"mutation/status", "complete"}},
		"base test FAILS without evidence":      {{"base_tests/tests/0/evidence_id", d}},
		"base test unknown change":              {{"base_tests/tests/0/change", "masked"}},
		"base tests unknown status":             {{"base_tests/status", "not_requested"}},
		"impacted test PASSES without evidence": {{"impact/changed_functions/0/tests/0/evidence_id", d}},
		"impact caller depth 4":                 {{"impact/changed_functions/0/callers/0/depth", 4}},
		"impact more than 10 callers":           {{"impact/changed_functions/0/callers", manyCallers}},
		"impact unknown status":                 {{"impact/status", "complete"}},
		"impact unknown tests status":           {{"impact/tests_status", "disabled"}},
		"parallelism 5":                         {{"execution/parallelism/requested", 5}},
		"cache scope":                           {{"execution/cache/scope", "all"}},
		"cache image not an ID":                 {{"execution/cache/image_id", "golang:1.26-bookworm"}},
		"duplicate replay-backed evidence":      {{"execution/replay_backed", []string{"evidence-4", "evidence-4"}}},
		"prepare short commit":                  {{"prepare/source_commit", "abc123"}},
		"prepare image not an ID":               {{"prepare/image_id", "golang:1.26"}},
		"prepare user":                          {{"prepare/user", "admin"}},
		"prepare unknown status":                {{"prepare/status", "skipped"}},
		"prepared input hash":                   {{"prepare/inputs/0/sha256", "ABC"}},
		"unknown root property":                 {{"confidence", 0.9}},
		"intent hash":                           {{"intent_sha256", "ABC"}},
		"more than 100 criteria":                {{"intent_criteria", manyCriteria}},
		"criterion without text":                {{"intent_criteria/0/text", ""}},
		"policy source":                         {{"policy/source", "model"}},
		"exit code 5":                           {{"exit_code", 5}},
	}
	return valid, invalid
}

// getJSONValue reads a value of the populated fixture, for edits that copy one.
func getJSONValue(t *testing.T, path string) any {
	t.Helper()
	return getJSON(toJSONValue(t, populatedReport()), path)
}

func applyEdits(t *testing.T, edits []edit) any {
	t.Helper()
	doc := toJSONValue(t, populatedReport())
	for _, e := range edits {
		setJSON(t, doc, e.path, e.value)
	}
	return doc
}

func TestSchemaAcceptsRecordedReports(t *testing.T) {
	v := newValidator(loadSchema(t))
	valid, _ := schemaCases(t)
	for name, edits := range valid {
		if errs := v.validateDocument(applyEdits(t, edits)); len(errs) > 0 {
			sort.Strings(errs)
			t.Errorf("%s: the schema rejects a report a run could record:\n  %s", name, strings.Join(errs, "\n  "))
		}
	}
}

func TestSchemaRejectsInconsistentRecords(t *testing.T) {
	v := newValidator(loadSchema(t))
	_, invalid := schemaCases(t)
	for name, edits := range invalid {
		errs := v.validateDocument(applyEdits(t, edits))
		if len(errs) == 0 {
			t.Errorf("%s: the schema accepts it", name)
			continue
		}
		sort.Strings(errs)
		t.Logf("%s: rejected: %s", name, strings.Join(errs, "; "))
	}
}

// TestSchemaFixturesDump writes the valid and invalid fixtures to
// SWIFTPROOF_TEST_SCHEMA_DUMP so that an independent Draft 2020-12 validator
// can confirm the stdlib validator's verdicts. It is skipped when unset.
func TestSchemaFixturesDump(t *testing.T) {
	dir := os.Getenv("SWIFTPROOF_TEST_SCHEMA_DUMP")
	if dir == "" {
		t.Skip("SWIFTPROOF_TEST_SCHEMA_DUMP is not set")
	}
	valid, invalid := schemaCases(t)
	write := func(prefix string, cases map[string][]edit) {
		for name, edits := range cases {
			data, err := json.MarshalIndent(applyEdits(t, edits), "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			file := prefix + "-" + strings.ReplaceAll(name, " ", "_") + ".json"
			if err := os.WriteFile(filepath.Join(dir, file), data, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	write("valid", valid)
	write("invalid", invalid)
}

// TestSchemaValidatesReportFiles validates real report files, for example the
// confidence-report.json of an end-to-end run, listed in
// SWIFTPROOF_TEST_SCHEMA_REPORTS (separated by the OS path-list separator).
func TestSchemaValidatesReportFiles(t *testing.T) {
	list := os.Getenv("SWIFTPROOF_TEST_SCHEMA_REPORTS")
	if list == "" {
		t.Skip("SWIFTPROOF_TEST_SCHEMA_REPORTS is not set")
	}
	v := newValidator(loadSchema(t))
	for _, file := range filepath.SplitList(list) {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if errs := v.validateDocument(decodeJSON(t, data)); len(errs) > 0 {
			sort.Strings(errs)
			t.Errorf("%s does not validate:\n  %s", file, strings.Join(errs, "\n  "))
		} else {
			t.Logf("%s validates", file)
		}
	}
}

// TestReplayed covers the frozen Check.Replayed rule: only a cache hit is a
// replay; a stored (live) check and a check without cache are not.
func TestReplayed(t *testing.T) {
	cases := []struct {
		cache *CheckCache
		want  bool
	}{
		{nil, false},
		{&CheckCache{Status: CacheStored, LiveRuns: 1}, false},
		{&CheckCache{Status: CacheHit, LiveRuns: 2}, true},
		{&CheckCache{Status: "HIT"}, false},
		{&CheckCache{}, false},
	}
	for _, tc := range cases {
		if got := (Check{Cache: tc.cache}).Replayed(); got != tc.want {
			t.Errorf("Replayed() with cache %+v = %v, want %v", tc.cache, got, tc.want)
		}
	}
}

func TestValidCriterionID(t *testing.T) {
	re := regexp.MustCompile(`^AC-[1-9][0-9]{0,2}$`)
	for _, id := range []string{"AC-1", "AC-9", "AC-10", "AC-99", "AC-100", "AC-999", "AC-0", "AC-01", "AC-1000", "AC-", "ac-1", "AC-1a", "AC1", "XAC-1", "AC-1 ", " AC-1", "AC--1", "AC-12\n", ""} {
		if got, want := ValidCriterionID(id), re.MatchString(id); got != want {
			t.Errorf("ValidCriterionID(%q) = %v, want %v", id, got, want)
		}
	}
	for i := 1; i <= 999; i++ {
		if !ValidCriterionID(fmt.Sprintf("AC-%d", i)) {
			t.Fatalf("AC-%d rejected", i)
		}
	}
}

// TestNewReportArraysSerializeAsArrays covers the always-present v0.4 arrays
// of a report built with empty slices, and that opt-in sections are absent
// until a run records them ("present means requested").
func TestNewReportArraysSerializeAsArrays(t *testing.T) {
	r := Report{IntentCriteria: []IntentCriterion{}, Divergences: []Divergence{}, IntentTestFailures: []Hypothesis{}}
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"intent_criteria", "divergences", "intent_test_failures"} {
		if string(m[key]) != "[]" {
			t.Errorf("%s = %s, want []", key, m[key])
		}
	}
	for _, key := range []string{"prepare", "base_tests", "mutation", "fuzz", "impact", "execution", "intent_sha256"} {
		if _, ok := m[key]; ok {
			t.Errorf("%s is present in a report that did not request it", key)
		}
	}
	var c map[string]json.RawMessage
	cd, _ := json.Marshal(Check{ID: "check-1"})
	_ = json.Unmarshal(cd, &c)
	if _, ok := c["cache"]; ok {
		t.Error("a check without cache serializes a cache object")
	}
}
