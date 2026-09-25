package report

import (
	"bytes"

	"github.com/gvinsot/SwiftProof/app/internal/model"
)

// This file belongs to F7a (execution cache). The F0 bodies below are
// behavior-safe stubs: they record and render nothing.

// finalizeExecution lists, sorted, every verified evidence ID whose negative
// conclusion rests on a replayed baseline in r.Execution.ReplayBacked, and
// normalizes the execution notes. It may mutate only r.Execution and never
// changes a status or the exit code (F7a).
func finalizeExecution(r *model.Report, l *ledger) {}

// cacheNote returns the note rendered under a stored or replayed check in
// "## Automated Checks", or "" (F7a). It returns plain, unescaped text:
// renderMarkdown indents it and passes it through inline().
func cacheNote(c model.Check) string {
	return ""
}

// writeExecution renders the execution summary at the end of "## Automated
// Checks", including the replay-backed evidence IDs when there are any (F7a).
func writeExecution(b *bytes.Buffer, r *model.Report) {}
