package report

import (
	"encoding/json"
	"fmt"

	"github.com/gvinsot/SwiftProof/app/internal/model"
)

// Report formats. ValidFormat is the single whitelist that the cli flags and
// Write use.
const (
	FormatMarkdown = "markdown"
	FormatJSON     = "json"
)

// writeOptions carries per-write rendering options.
type writeOptions struct {
	reportURL string
}

// Option configures one Write call.
type Option func(*writeOptions)

// WithReportURL records the link to the full report that a PR-comment render
// may cite. The cli validates it before any report is written.
func WithReportURL(url string) Option {
	return func(o *writeOptions) { o.reportURL = url }
}

// ValidFormat reports whether format names a report format this build renders.
func ValidFormat(format string) bool {
	switch format {
	case FormatMarkdown, FormatJSON:
		return true
	}
	return false
}

// renderFormat renders one format of an already sanitized report into memory.
// It returns the file name to write inside the output directory.
func renderFormat(format string, r *model.Report, o writeOptions) (string, []byte, error) {
	switch format {
	case FormatMarkdown:
		return "CONFIDENCE_REPORT.md", renderMarkdown(r), nil
	case FormatJSON:
		data, err := json.MarshalIndent(r, "", "  ")
		if err != nil {
			return "", nil, err
		}
		return "confidence-report.json", append(data, '\n'), nil
	}
	return "", nil, fmt.Errorf("unsupported report format %q", format)
}
