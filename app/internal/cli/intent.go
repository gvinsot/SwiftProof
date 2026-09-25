package cli

// F0 stub of the intent parsing (F5 owns this file). The stub keeps the intent
// text as given and extracts no acceptance criteria, so no intent test tool is
// offered to the reviewer.

import "github.com/gvinsot/SwiftProof/app/internal/model"

// intentDoc is the parsed --intent / --intent-file text.
type intentDoc struct {
	Text     string                  // the intent recorded in the report
	SHA256   string                  // hex sha256 of Text; "" when not computed
	Criteria []model.IntentCriterion // acceptance criteria, in order
	Notes    []string                // Unverified entries about the parsing
}

// parseIntent parses the intent text. An error exits 3 ("intent: ...").
func parseIntent(text string) (intentDoc, error) {
	return intentDoc{Text: text}, nil
}

// intentLine is the stdout line about intent tests; the stub prints none.
func intentLine(r *model.Report) string { return "" }
