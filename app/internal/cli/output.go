package cli

// F0 stub of the export options (F9 owns this file). This build renders only
// markdown and json, so a report URL has nothing to attach to.

import (
	"errors"

	"github.com/gvinsot/SwiftProof/app/internal/report"
)

// reportOptions validates --report-url against the requested formats and
// returns the report.Write options. Its error exits 3 before anything runs.
func reportOptions(formats []string, url string) ([]report.Option, error) {
	if url != "" {
		return nil, errors.New("--report-url requires --format pr-comment")
	}
	return nil, nil
}
