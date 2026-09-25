package harness

// F0 stub of the initial-check batch (F7b owns this file).

import (
	"context"

	"github.com/gvinsot/SwiftProof/app/internal/model"
)

// RunChecks runs the configured initial checks of kinds in the given order and
// returns their recorded checks. The stub is sequential: each kind runs as Run
// does, including its audit event.
func (h *Harness) RunChecks(ctx context.Context, kinds []string) []model.Check {
	checks := make([]model.Check, 0, len(kinds))
	for _, kind := range kinds {
		checks = append(checks, h.Run(ctx, kind))
	}
	return checks
}
