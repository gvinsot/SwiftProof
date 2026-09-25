package report

import (
	"bytes"

	"github.com/gvinsot/SwiftProof/app/internal/model"
)

// This file belongs to F8 (trusted prepare stage). The F0 bodies below are
// behavior-safe stubs: they render and change nothing.

// writePrepare renders "## Dependency Preparation" when r.Prepare is present.
// It follows the Change Summary, which already ends with a blank line (F8).
func writePrepare(b *bytes.Buffer, r *model.Report) {}

// finalizePrepare normalizes the prepare notes only. It may mutate only
// r.Prepare (F8).
func finalizePrepare(r *model.Report) {}
