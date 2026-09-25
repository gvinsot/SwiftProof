package linter

// F0 stub of the lexical test-weakening signals (F3 owns this file).

import "github.com/gvinsot/SwiftProof/app/internal/model"

// testWeakeningSignals returns heuristic signals for a changed test file whose
// edits may weaken it (removed assertions or cases, added skips or focus,
// relaxed expectations). They are review prompts, never evidence. The stub
// returns none.
func testWeakeningSignals(f model.ChangedFile) []model.Signal { return nil }
