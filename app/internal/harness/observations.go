package harness

// F0 stub of the observation oracle (F1 owns this file).

import (
	"context"

	"github.com/gvinsot/SwiftProof/app/internal/model"
)

type observeState struct{}

// observeGenerated compares the values a generated test recorded on the
// baseline and the candidate. It runs while the generated file is still
// staged. The stub records nothing and returns nil.
func (h *Harness) observeGenerated(ctx context.Context, t *generatedTest, runner string, command, names []string, base, candidate model.Check) map[string]any {
	return nil
}
