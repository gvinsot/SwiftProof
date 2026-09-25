// Package report turns recorded observations into a conservative, portable review report.
package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"unicode"

	"github.com/gvinsot/SwiftProof/app/internal/coverage"
	"github.com/gvinsot/SwiftProof/app/internal/harness"
	"github.com/gvinsot/SwiftProof/app/internal/model"
)

// Finalize derives conclusions from recorded evidence, never from a model's asserted status.
// It is idempotent, including when re-rendering a persisted report.
func Finalize(r *model.Report, ci bool) {
	r.Version = 1
	r.ReproducedIssues = nil
	r.ReviewTargets = nil
	r.ExitCode = 0
	checks := make(map[string]model.Check, len(r.Checks))
	duplicateChecks := map[string]bool{}
	for _, c := range r.Checks {
		if _, exists := checks[c.ID]; exists {
			duplicateChecks[c.ID] = true
		}
		checks[c.ID] = c
	}
	evidence := make(map[string]model.Evidence, len(r.Evidence))
	duplicateEvidence := map[string]bool{}
	for _, e := range r.Evidence {
		if _, exists := evidence[e.ID]; exists {
			duplicateEvidence[e.ID] = true
		}
		evidence[e.ID] = e
	}
	needsHuman := len(r.Unverified) > 0
	for i := range r.Hypotheses {
		h := &r.Hypotheses[i]
		h.Severity = severity(h.Severity)
		claimed := strings.ToUpper(h.Status)
		valid := len(h.EvidenceIDs) > 0
		proved, tested, observed := false, false, false
		for _, id := range h.EvidenceIDs {
			e, ok := evidence[id]
			if !ok || id == "" || duplicateEvidence[id] {
				valid = false
				continue
			}
			candidate, cok := checks[e.CheckID]
			base, bok := checks[e.BaseCheckID]
			differential := e.Kind == "differential_test" && e.Runner == "go_test_json" && len(e.TestNames) > 0 && cok && bok && !duplicateChecks[e.CheckID] && !duplicateChecks[e.BaseCheckID] && candidate.Kind == "generated_test_candidate" && base.Kind == "generated_test_base" && equalCommand(candidate.Command, base.Command)
			if differential {
				candidate = harness.ValidateGoExecution(candidate, e.TestNames)
				base = harness.ValidateGoExecution(base, e.TestNames)
			}
			if differential && base.Status == "PASS" && base.ExitCode == 0 {
				proved = proved || e.Status == "REPRODUCED" && candidate.Status == "FAIL" && candidate.ExitCode > 0 && candidate.ExitCode < 125
				tested = tested || e.Status == "NOT_REPRODUCED" && candidate.Status == "PASS" && candidate.ExitCode == 0
			}
			// A source observation can support a dismissal, but is not executable proof.
			observed = observed || e.Kind == "source_observation" && e.Status == "OBSERVED" && e.Output != ""
		}
		switch {
		case claimed == "REPRODUCED" && valid && proved:
			h.Status = "REPRODUCED"
			r.ReproducedIssues = append(r.ReproducedIssues, *h)
			if rank(h.Severity) >= rank("high") {
				r.ExitCode = 1
			}
		case claimed == "NOT_REPRODUCED" && valid && tested:
			h.Status = "NOT_REPRODUCED"
		case claimed == "DISMISSED" && valid && observed && strings.TrimSpace(h.Rationale) != "":
			h.Status = "DISMISSED"
		default:
			h.Status = "UNVERIFIED"
			needsHuman = true
		}
	}
	for _, c := range r.Checks {
		if c.Status != "PASS" || c.ExitCode != 0 {
			needsHuman = true
		}
	}
	for _, s := range r.Signals {
		if rank(s.Severity) >= rank("high") {
			needsHuman = true
		}
	}
	r.Unverified = unique(r.Unverified)
	r.ReviewTargets, r.ReviewSurface = targets(r)
	// Coverage is recorded upstream and never recomputed here; a report written
	// before this field existed is normalized to "nothing was measured".
	if r.Coverage.Status == "" {
		r.Coverage.Status = coverage.StatusNotConfigured
	}
	if r.Coverage.Note == "" {
		r.Coverage.Note = coverage.Note
	}
	if r.Coverage.Files == nil {
		r.Coverage.Files = []model.CoverageFile{}
	}
	if len(r.Change.Files) > 0 && len(r.Checks) == 0 {
		needsHuman = true
	}
	if r.ExitCode == 0 && ci && needsHuman {
		r.ExitCode = 2
	}
}

func equalCommand(a, b []string) bool {
	if len(a) == 0 || len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

type coordinate struct {
	path, side string
	line       int
}

func targets(r *model.Report) ([]model.ReviewTarget, model.ReviewSurface) {
	changed := map[coordinate]bool{}
	for _, f := range r.Change.Files {
		for _, h := range f.Hunks {
			for _, l := range h.Lines {
				switch l.Kind {
				case "add", "addition", "+":
					if l.NewLine > 0 {
						changed[coordinate{f.Path, "new", l.NewLine}] = true
					}
				case "delete", "deletion", "remove", "-":
					p := f.OldPath
					if p == "" {
						p = f.Path
					}
					if l.OldLine > 0 {
						changed[coordinate{p, "old", l.OldLine}] = true
					}
				}
			}
		}
	}
	byFile := map[[2]string][]coordinate{}
	for c := range changed {
		key := [2]string{c.path, c.side}
		byFile[key] = append(byFile[key], c)
	}
	for _, coordinates := range byFile {
		sort.Slice(coordinates, func(i, j int) bool { return coordinates[i].line < coordinates[j].line })
	}
	selected := map[coordinate]*model.ReviewTarget{}
	add := func(path, side string, start, end int, sev, reason, id string) {
		if path == "" {
			return
		}
		if side != "old" {
			side = "new"
		}
		if end < start {
			end = start
		}
		found := false
		coordinates := byFile[[2]string{path, side}]
		if start > 0 {
			lo := sort.Search(len(coordinates), func(i int) bool { return coordinates[i].line >= start })
			hi := sort.Search(len(coordinates), func(i int) bool { return coordinates[i].line > end })
			coordinates = coordinates[lo:hi]
		}
		for _, c := range coordinates {
			found = true
			t := selected[c]
			if t == nil {
				t = &model.ReviewTarget{Path: path, Side: side, StartLine: c.line, EndLine: c.line, Severity: severity(sev)}
				selected[c] = t
			}
			if rank(sev) > rank(t.Severity) {
				t.Severity = severity(sev)
			}
			t.Reasons = append(t.Reasons, reason)
			if id != "" {
				t.SignalIDs = append(t.SignalIDs, id)
			}
		}
		// Keep a useful human target when the observation refers to context, a binary, or a file.
		if !found {
			c := coordinate{path, side, start}
			t := selected[c]
			if t == nil {
				t = &model.ReviewTarget{Path: path, Side: side, StartLine: start, EndLine: end, Severity: severity(sev)}
				selected[c] = t
			}
			if rank(sev) > rank(t.Severity) {
				t.Severity = severity(sev)
			}
			t.Reasons = append(t.Reasons, reason)
			if id != "" {
				t.SignalIDs = append(t.SignalIDs, id)
			}
		}
	}
	for _, s := range r.Signals {
		add(s.Path, s.Side, s.Line, s.EndLine, s.Severity, s.Summary, s.ID)
	}
	for _, h := range r.Hypotheses {
		if h.Status == "UNVERIFIED" || h.Status == "REPRODUCED" {
			add(h.Path, "new", h.Line, h.Line, h.Severity, h.Title, "")
		}
	}
	var out []model.ReviewTarget
	focused := 0
	for c, t := range selected {
		if changed[c] {
			focused++
		}
		t.Reasons = unique(t.Reasons)
		t.SignalIDs = unique(t.SignalIDs)
		out = append(out, *t)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		if a.Side != b.Side {
			return a.Side < b.Side
		}
		return a.StartLine < b.StartLine
	})
	var merged []model.ReviewTarget
	for _, t := range out {
		if len(merged) > 0 {
			last := &merged[len(merged)-1]
			if last.Path == t.Path && last.Side == t.Side && t.StartLine > 0 && last.EndLine+1 >= t.StartLine {
				if t.EndLine > last.EndLine {
					last.EndLine = t.EndLine
				}
				if rank(t.Severity) > rank(last.Severity) {
					last.Severity = t.Severity
				}
				last.Reasons = unique(append(last.Reasons, t.Reasons...))
				last.SignalIDs = unique(append(last.SignalIDs, t.SignalIDs...))
				continue
			}
		}
		merged = append(merged, t)
	}
	sort.SliceStable(merged, func(i, j int) bool { return rank(merged[i].Severity) > rank(merged[j].Severity) })
	return merged, model.ReviewSurface{ChangedLines: len(changed), FocusedLines: focused, Note: "Distinct changed coordinates; removed and added lines count separately. Focused review is a prioritization aid, not proof that the remaining diff is correct. NOT_REPRODUCED means only that the recorded experiment did not reproduce the concern."}
}

func rank(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}
func severity(s string) string {
	s = strings.ToLower(s)
	if rank(s) == 0 {
		return "medium"
	}
	return s
}
func unique(values []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, v := range values {
		if v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}

// Markdown renders repository/model strings as escaped text; it never emits remote images or raw HTML.
func Markdown(r *model.Report) []byte {
	r = Sanitize(r)
	var b bytes.Buffer
	line(&b, "# Change Confidence Report\n")
	fmt.Fprintf(&b, "## Change Summary\n\n%d additions / %d deletions · %d files changed\n\n", r.Change.Additions, r.Change.Deletions, len(r.Change.Files))
	fmt.Fprintf(&b, "Base: %s\n\nCandidate: %s\n\n", inline(r.Change.BaseCommit), inline(r.Change.HeadCommit))
	if r.Intent != "" {
		fmt.Fprintf(&b, "Intent: %s\n\n", inline(r.Intent))
	}
	fmt.Fprintf(&b, "Exit code: %d. No confidence percentage is assigned.\n\n", r.ExitCode)
	line(&b, "## Automated Checks\n")
	if len(r.Checks) == 0 {
		line(&b, "No checks were executed.\n")
	}
	for _, c := range r.Checks {
		fmt.Fprintf(&b, "- **%s** %s (%s; exit %d; %d ms)\n", inline(c.Status), inline(c.Kind), inline(c.ID), c.ExitCode, c.DurationMS)
		if c.Truncated {
			line(&b, "  Output was truncated.")
		}
	}
	line(&b, "\n## Investigation Summary\n")
	if len(r.Hypotheses) == 0 {
		line(&b, "No structured hypotheses were investigated.\n")
	}
	for _, h := range r.Hypotheses {
		fmt.Fprintf(&b, "- **%s / %s** %s (%s): %s\n", inline(h.Status), inline(h.Severity), inline(h.Title), inline(h.ID), inline(h.Rationale))
	}
	line(&b, "\n## Reproduced Issues\n")
	if len(r.ReproducedIssues) == 0 {
		line(&b, "No issue was reproduced by a passing baseline and failing candidate experiment.\n")
	}
	for _, h := range r.ReproducedIssues {
		fmt.Fprintf(&b, "- **%s** %s — %s:%d\n  Evidence: %s\n", inline(h.Severity), inline(h.Title), inline(h.Path), h.Line, inline(strings.Join(h.EvidenceIDs, ", ")))
	}
	line(&b, "\n## Unverified Areas\n")
	n := 0
	for _, u := range r.Unverified {
		fmt.Fprintf(&b, "- %s\n", inline(u))
		n++
	}
	for _, h := range r.Hypotheses {
		if h.Status == "UNVERIFIED" {
			fmt.Fprintf(&b, "- %s: %s\n", inline(h.Title), inline(h.Rationale))
			n++
		}
	}
	for _, c := range r.Checks {
		if c.Status != "PASS" {
			fmt.Fprintf(&b, "- Check %s is %s; inspect recorded output.\n", inline(c.ID), inline(c.Status))
			n++
		}
	}
	if n == 0 {
		line(&b, "No specific unresolved area was recorded. This does not establish correctness.")
	}
	line(&b, "\n## Suggested Human Review\n")
	if len(r.ReviewTargets) == 0 {
		line(&b, "No location was prioritized by the available signals. Review intent and behavior before merging.\n")
	}
	for _, t := range r.ReviewTargets {
		fmt.Fprintf(&b, "- **%s** %s:%d–%d (%s): %s\n", inline(t.Severity), inline(t.Path), t.StartLine, t.EndLine, inline(t.Side), inline(strings.Join(t.Reasons, "; ")))
	}
	fmt.Fprintf(&b, "\n## Review Surface\n\nFocused review: **%d / %d changed lines**.\n\n%s\n", r.ReviewSurface.FocusedLines, r.ReviewSurface.ChangedLines, inline(r.ReviewSurface.Note))
	line(&b, "\n## Changed-line Execution\n")
	switch r.Coverage.Status {
	case coverage.StatusMeasured:
		fmt.Fprintf(&b, "Measured from check %s: of %d added Go lines, %d were executed at least once, %d were not executed, %d are not inside any instrumented block, %d could not be measured. %d removed lines cannot be executed by a candidate-side run and are excluded.\n\n",
			inline(r.Coverage.CheckID), r.Coverage.AddedLines, r.Coverage.ExecutedLines, r.Coverage.NotExecutedLines, r.Coverage.NoBlockLines, r.Coverage.NotMeasuredLines, r.Coverage.RemovedLines)
		// The list is filtered, so it says what it lists: a reader must not take
		// a short list for a complete per-file breakdown. The counters above
		// cover every file; the coverage JSON carries the full per-file table.
		listed := 0
		for _, f := range r.Coverage.Files {
			if f.NotExecutedLines == 0 && f.Status != coverage.StatusNotMeasured {
				continue
			}
			if listed == 0 {
				line(&b, "Files with added lines that were not executed, or that could not be measured:\n")
			}
			listed++
			fmt.Fprintf(&b, "- %s: %d executed, %d not executed, %d not inside any instrumented block, %d not measured\n", inline(f.Path), f.ExecutedLines, f.NotExecutedLines, f.NoBlockLines, f.NotMeasuredLines)
		}
		fmt.Fprintf(&b, "\n%s\n", inline(r.Coverage.Note))
	case coverage.StatusNotMeasured:
		if strings.TrimSpace(r.Coverage.Reason) == "" {
			line(&b, "Changed-line execution was not measured. No reason was recorded.")
			break
		}
		fmt.Fprintf(&b, "Changed-line execution was not measured: %s\n", inline(r.Coverage.Reason))
	default:
		line(&b, "No coverage command is configured, so changed-line execution was not measured.")
	}
	line(&b, "\n## Recorded Evidence\n")
	for _, e := range r.Evidence {
		fmt.Fprintf(&b, "- %s — %s (%s): %s\n", inline(e.ID), inline(e.Kind), inline(e.Status), inline(e.Description))
		if e.CheckID != "" {
			fmt.Fprintf(&b, "  Candidate check: %s; baseline check: %s\n", inline(e.CheckID), inline(e.BaseCheckID))
		}
	}
	if len(r.Artifacts) > 0 {
		line(&b, "\n## Artifacts\n")
		for _, a := range r.Artifacts {
			fmt.Fprintf(&b, "- %s (%s)\n", inline(a.Path), inline(a.Kind))
		}
	}
	return b.Bytes()
}

func inline(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == '\u202e' || r == '\u202d' || r == '\u2066' || r == '\u2067' || r == '\u2068' || r == '\u2069' {
			return ' '
		}
		return r
	}, s)
	s = html.EscapeString(s)
	return strings.NewReplacer("\\", "\\\\", "`", "\\`", "*", "\\*", "_", "\\_", "[", "\\[", "]", "\\]", "(", "\\(", ")", "\\)", "#", "\\#", "|", "\\|", "!", "\\!").Replace(s)
}

func line(b *bytes.Buffer, s string) { b.WriteString(s); b.WriteByte('\n') }

// Write replaces each report atomically. It validates all formats before touching disk.
func Write(dir string, r *model.Report, formats []string) error {
	r = Sanitize(r)
	if len(formats) == 0 {
		formats = []string{"markdown", "json"}
	}
	for _, format := range formats {
		if format != "markdown" && format != "json" {
			return fmt.Errorf("unsupported report format %q", format)
		}
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	for _, format := range unique(formats) {
		name := "CONFIDENCE_REPORT.md"
		data := Markdown(r)
		if format == "json" {
			name = "confidence-report.json"
			var err error
			data, err = json.MarshalIndent(r, "", "  ")
			if err != nil {
				return err
			}
			data = append(data, '\n')
		}
		if err := atomicWrite(filepath.Join(dir, name), data); err != nil {
			return err
		}
	}
	return nil
}

// Sanitize returns a deep copy suitable for disk or provider transmission. Whole
// diff contents are hidden for sensitive filenames; other strings receive the
// same best-effort secret redaction as harness observations.
func Sanitize(r *model.Report) *model.Report {
	if r == nil {
		r = &model.Report{}
	}
	data, _ := json.Marshal(r)
	var safe model.Report
	_ = json.Unmarshal(data, &safe)
	for i := range safe.Change.Files {
		f := &safe.Change.Files[i]
		if !harness.IsSensitivePath(f.Path) && !harness.IsSensitivePath(f.OldPath) {
			continue
		}
		for j := range f.Hunks {
			for k := range f.Hunks[j].Lines {
				f.Hunks[j].Lines[k].Content = "[REDACTED: sensitive file]"
			}
		}
	}
	for i := range safe.Signals {
		if harness.IsSensitivePath(safe.Signals[i].Path) {
			safe.Signals[i].Evidence = "[REDACTED: sensitive file]"
		}
	}
	redactValue(reflect.ValueOf(&safe).Elem())
	return &safe
}

func redactValue(v reflect.Value) {
	switch v.Kind() {
	case reflect.String:
		if v.CanSet() {
			v.SetString(harness.Redact(v.String()))
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if v.Field(i).CanSet() {
				redactValue(v.Field(i))
			}
		}
	case reflect.Slice:
		if v.IsNil() && v.CanSet() {
			v.Set(reflect.MakeSlice(v.Type(), 0, 0))
		}
		for i := 0; i < v.Len(); i++ {
			redactValue(v.Index(i))
		}
	case reflect.Pointer:
		if !v.IsNil() {
			redactValue(v.Elem())
		}
	}
}

func atomicWrite(path string, data []byte) (err error) {
	f, err := os.CreateTemp(filepath.Dir(path), ".swiftproof-report-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
