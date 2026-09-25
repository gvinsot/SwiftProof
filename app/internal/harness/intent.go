package harness

// F0 stub of the candidate-only intent tests (F5 owns this file).

import (
	"context"
	"errors"
)

// Reviewer tool names of the intent tests.
const IntentCreateTool = "create_intent_test"
const IntentRunTool = "run_intent_test"

// IsIntentTool reports whether name is one of the intent-test tools, which a
// reviewer is offered only when the run has acceptance criteria.
func IsIntentTool(name string) bool { return name == IntentCreateTool || name == IntentRunTool }

type intentState struct{}

var errIntentUnavailable = errors.New("intent tests require acceptance criteria")

// createIntentTest registers a candidate-only test for one acceptance
// criterion. The stub refuses every call.
func (h *Harness) createIntentTest(criterionID, path, content, description string) (any, error) {
	return nil, errIntentUnavailable
}

// runIntentTest runs a registered intent test on the candidate only. The stub
// refuses every call.
func (h *Harness) runIntentTest(ctx context.Context, id string) (any, error) {
	return nil, errIntentUnavailable
}

// intentToolDefinitions returns the reviewer tool definitions of the intent
// tests. The stub offers none.
func intentToolDefinitions() []map[string]any { return nil }
