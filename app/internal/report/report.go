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
	"github.com/gvinsot/SwiftProof/app/internal/redact"
)

// Finalize derives conclusions from recorded evidence, never from a model's asserted status.
// It is idempotent, including when re-rendering a persisted report.
//
// Every evidence record is first re-derived from the recorded checks by the
// verifier that owns its kind. Only a status a verifier re-derived, and that
// equals the stored one, can support a hypothesis (see accepted), a divergence
// or a section item. Only a REPRODUCED high or critical hypothesis sets exit 1;
// with ci, anything that needs a human sets exit 2 when the code is still 0.
func Finalize(r *model.Report, ci bool) {
	r.Version, r.ExitCode = 1, 0
	r.ReproducedIssues, r.Divergences, r.IntentTestFailures, r.ReviewTargets = nil, nil, nil, nil
	conclude(r, verifyReport(r), ci, buildDivergences)
}

// conclude assigns the final hypothesis statuses, the Finalize-derived
// sections and the exit code from a verified ledger. divergences is
// buildDivergences in production; tests substitute a fixed feed.
//
// The divergence entries are validated before any hypothesis is concluded: a
// DIVERGED claim is accepted only when it cites an entry that the Behavior
// Divergences section lists, so the two can never disagree. The entries are
// linked to their citing hypotheses once every status is final.
func conclude(r *model.Report, l *ledger, ci bool, divergences func(*model.Report, *ledger) []model.Divergence) {
	criteria := criterionIndex(r.IntentCriteria) // valid IDs occurring exactly once
	needsHuman := len(r.Unverified) > 0
	entries := divergences(r, l) // F0; fed by observationDivergences (F1) + fuzzDivergences (F2)
	listed := make(map[string]bool, len(entries))
	for _, d := range entries {
		listed[d.EvidenceID] = true
	}
	for i := range r.Hypotheses {
		h := &r.Hypotheses[i]
		h.Severity = severity(h.Severity)
		claimed := strings.ToUpper(h.Status)
		valid, supported := l.supports(h, claimed, criteria)
		switch {
		case claimed == model.StatusReproduced && valid && supported:
			h.Status = model.StatusReproduced
			if rank(h.Severity) >= rank("high") {
				r.ExitCode = 1
			}
		case claimed == model.StatusDiverged && valid && supported && citesAny(*h, listed):
			// A recorded difference, never a defect: it requests review and
			// never produces exit 1.
			h.Status = model.StatusDiverged
			needsHuman = true
		case claimed == model.StatusIntentTestFailed && valid && supported:
			// Candidate-only and model-written: it requests review and never
			// enters reproduced_issues.
			h.Status = model.StatusIntentTestFailed
			needsHuman = true
		case claimed == model.StatusNotReproduced && valid && supported:
			h.Status = model.StatusNotReproduced
		case claimed == model.StatusDismissed && valid && supported && strings.TrimSpace(h.Rationale) != "":
			h.Status = model.StatusDismissed
		default:
			h.Status = model.StatusUnverified
			needsHuman = true
		}
		// After the final status: drops intent_judgment unless the status is
		// DIVERGED, and drops a criterion_id that is not in criteria. Each drop
		// returns a fixed Unverified note (F5).
		if note := normalizeIntentLink(h, criteria); note != "" {
			r.Unverified = append(r.Unverified, note)
			needsHuman = true
		}
		// The derived lists copy the hypothesis only once it is normalized, so
		// that each copy equals its hypothesis and Finalize stays idempotent.
		switch h.Status {
		case model.StatusReproduced:
			r.ReproducedIssues = append(r.ReproducedIssues, *h)
		case model.StatusIntentTestFailed:
			r.IntentTestFailures = append(r.IntentTestFailures, *h)
		}
	}
	r.Divergences = linkDivergences(r, entries)
	if len(r.Divergences) > 0 {
		needsHuman = true
	}
	if finalizeBaseTests(r, l) { // F3
		needsHuman = true
	}
	if finalizeFuzz(r, l) { // F2
		needsHuman = true
	}
	if finalizeMutation(r, verifyMutation(r)) { // F4: unverified mutants become INCONCLUSIVE
		needsHuman = true
	}
	if finalizeImpact(r, l) { // F6a/F6b
		needsHuman = true
	}
	finalizeExecution(r, l) // F7a: replay_backed + note normalization
	finalizePrepare(r)      // F8: note normalization only
	// The mutation ledger is excluded: mutants are expected to fail.
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
		switch h.Status {
		case model.StatusUnverified, model.StatusReproduced, model.StatusDiverged, model.StatusIntentTestFailed:
			add(h.Path, "new", h.Line, h.Line, h.Severity, h.Title, "")
		}
	}
	for _, t := range extraTargets(r) {
		add(t.path, t.side, t.start, t.end, t.severity, t.reason, "")
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
	return renderMarkdown(Sanitize(r))
}

// renderMarkdown renders an already sanitized report. The section order is
// fixed; a v0.4 section writer emits its own heading ("\n## Title\n" followed
// by a blank line, like the surrounding sections) and every string it renders
// goes through inline().
func renderMarkdown(r *model.Report) []byte {
	// The statuses Finalize accepts, re-derived the same way, so that the
	// Behavior Divergences and Recorded Evidence texts never claim more.
	verified := verifyReport(r).verified
	var b bytes.Buffer
	line(&b, "# Change Confidence Report\n")
	fmt.Fprintf(&b, "## Change Summary\n\n%d additions / %d deletions · %d files changed\n\n", r.Change.Additions, r.Change.Deletions, len(r.Change.Files))
	fmt.Fprintf(&b, "Base: %s\n\nCandidate: %s\n\n", inline(r.Change.BaseCommit), inline(r.Change.HeadCommit))
	switch r.Policy.Source {
	case model.PolicyBaseRef:
		fmt.Fprintf(&b, "Policy: %s at %s (%s)\n\n", inline(r.Policy.Path), inline(r.Change.BaseRef), inline(r.Policy.Commit))
	case model.PolicyExplicit:
		fmt.Fprintf(&b, "Policy: explicit local file %s\n\n", inline(r.Policy.Path))
	case model.PolicyDefault:
		fmt.Fprintf(&b, "Policy: built-in defaults; no policy file at %s (%s)\n\n", inline(r.Change.BaseRef), inline(r.Policy.Commit))
	}
	if r.Intent != "" {
		fmt.Fprintf(&b, "Intent: %s\n\n", inline(r.Intent))
	}
	fmt.Fprintf(&b, "Exit code: %d. No confidence percentage is assigned.\n\n", r.ExitCode)
	if r.Prepare != nil {
		writePrepare(&b, r) // F8: "## Dependency Preparation"
	}
	line(&b, "## Automated Checks\n")
	if len(r.Checks) == 0 {
		line(&b, "No checks were executed.\n")
	}
	for _, c := range r.Checks {
		fmt.Fprintf(&b, "- **%s** %s (%s; exit %d; %d ms)\n", inline(c.Status), inline(c.Kind), inline(c.ID), c.ExitCode, c.DurationMS)
		if c.Truncated {
			line(&b, "  Output was truncated.")
		}
		if n := cacheNote(c); n != "" { // F7a: plain text, escaped here
			line(&b, "  "+inline(n))
		}
	}
	writeExecution(&b, r) // F7a
	line(&b, "\n## Investigation Summary\n")
	if len(r.Hypotheses) == 0 {
		line(&b, "No structured hypotheses were investigated.\n")
	}
	for _, h := range r.Hypotheses {
		fmt.Fprintf(&b, "- **%s / %s** %s (%s): %s\n", inline(h.Status), inline(h.Severity), inline(h.Title), inline(h.ID), inline(h.Rationale))
		writeIntentLink(&b, r, h) // F5
	}
	line(&b, "\n## Reproduced Issues\n")
	if len(r.ReproducedIssues) == 0 {
		line(&b, "No issue was reproduced by a passing baseline and failing candidate experiment.\n")
	}
	for _, h := range r.ReproducedIssues {
		fmt.Fprintf(&b, "- **%s** %s — %s:%d\n  Evidence: %s\n", inline(h.Severity), inline(h.Title), inline(h.Path), h.Line, inline(strings.Join(h.EvidenceIDs, ", ")))
		writeIntentLink(&b, r, h) // F5
	}
	if r.BaseTests != nil {
		writeBaseTests(&b, r) // F3: "## Changed Baseline Tests on Candidate Code"
	}
	writeDivergences(&b, r, verified) // F0: "## Behavior Divergences", always rendered
	if r.Intent != "" || len(r.IntentCriteria) > 0 || len(r.IntentTestFailures) > 0 {
		writeIntentSections(&b, r) // F5: "## Intent Test Failures" and "## Intent Criteria"
	}
	line(&b, "\n## Unverified Areas\n")
	n := 0
	for _, u := range r.Unverified {
		fmt.Fprintf(&b, "- %s\n", inline(u))
		n++
	}
	for _, h := range r.Hypotheses {
		if h.Status == model.StatusUnverified {
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
	if r.Mutation != nil {
		writeMutation(&b, r) // F4: "## Mutation of Added Lines"
	}
	if r.Fuzz != nil {
		writeFuzz(&b, r) // F2: "## Differential Fuzzing"
	}
	if r.Impact != nil {
		writeImpact(&b, r) // F6a: "## Impact Analysis"
	}
	line(&b, "\n## Recorded Evidence\n")
	for _, e := range r.Evidence {
		status := inline(e.Status)
		if e.Status != model.StatusUnverified && verified[e.ID] != e.Status {
			status += "; " + notAcceptedText
		}
		fmt.Fprintf(&b, "- %s — %s (%s): %s\n", inline(e.ID), inline(e.Kind), status, inline(e.Description))
		if l := evidenceCheckLine(e); l != "" {
			line(&b, "  "+l)
		}
	}
	if len(r.Artifacts) > 0 {
		line(&b, "\n## Artifacts\n")
		for _, a := range r.Artifacts {
			fmt.Fprintf(&b, "- %s (%s)\n", inline(a.Path), inline(a.Kind))
		}
	}
	// Attribution notice required by the section 7(b) term in NOTICE.
	line(&b, "\n---\n")
	fmt.Fprintf(&b, "%s\n", Attribution(r.ToolVersion))
	return b.Bytes()
}

// Fixed texts of the Behavior Divergences section and of Recorded Evidence.
const (
	noExperimentText = "No observation or fuzz experiment was recorded."
	noDivergenceText = "No recorded experiment diverged. Where values were compared, they were equal for the recorded inputs; values are bounded, redacted serializations, and this does not establish equivalent behavior, even for those inputs."
	// unvalidatedText replaces noDivergenceText when an observation or fuzz
	// record has no accepted NOT_DIVERGED status (unverified, unstable or
	// incomparable values, or a stored status the recorded checks do not
	// support): nothing may then be said about equal values.
	unvalidatedText = "No validated divergence was recorded. %d of %d observation or fuzz records did not yield a validated result (see Recorded Evidence and Unverified Areas); this does not establish equivalent behavior."
	// notAcceptedText follows a stored evidence status that Finalize did not
	// accept: not re-derived from the recorded checks, or withdrawn.
	notAcceptedText = "as stored; not accepted as evidence"
	// maxDivergenceRowsShown caps the value rows rendered per divergence; the
	// JSON keeps every validated row.
	maxDivergenceRowsShown = 20
)

// writeDivergences renders the always-present Behavior Divergences section
// from r.Divergences, which only Finalize fills with validated entries, and
// verified, the evidence statuses Finalize accepts. Without an entry, it says
// that values were equal only when every observation or fuzz record has an
// accepted NOT_DIVERGED status. Every string goes through inline(); it emits
// no code span and no link.
func writeDivergences(b *bytes.Buffer, r *model.Report, verified map[string]string) {
	line(b, "\n## Behavior Divergences\n")
	if len(r.Divergences) == 0 {
		recorded, unvalidated := 0, 0
		for _, e := range r.Evidence {
			if e.Kind != model.EvidenceDifferentialObservation && e.Kind != model.EvidenceDifferentialFuzz {
				continue
			}
			recorded++
			if verified[e.ID] != model.StatusNotDiverged {
				unvalidated++
			}
		}
		switch {
		case recorded == 0:
			line(b, noExperimentText)
		case unvalidated == 0:
			line(b, noDivergenceText)
		default:
			line(b, fmt.Sprintf(unvalidatedText, unvalidated, recorded))
		}
		return
	}
	for _, d := range r.Divergences {
		anchor := "no anchor"
		if d.Path != "" {
			anchor = inline(d.Path)
			if d.Line > 0 {
				anchor += fmt.Sprintf(":%d", d.Line)
			}
			if d.AnchorSource == anchorChangedFunction {
				anchor += " (changed function)"
			} else {
				anchor += " (model-chosen location)"
			}
		}
		hypotheses := "none"
		if len(d.HypothesisIDs) > 0 {
			hypotheses = inline(strings.Join(d.HypothesisIDs, ", "))
		}
		fmt.Fprintf(b, "- **%s** %s — %s; test %s (%s); hypotheses: %s\n", inline(d.EvidenceID), inline(d.Kind), anchor, inline(d.TestPath), inline(strings.Join(d.TestNames, ", ")), hypotheses)
		for i, o := range d.Observations {
			if i == maxDivergenceRowsShown {
				fmt.Fprintf(b, "  - … %d more in confidence-report.json\n", len(d.Observations)-maxDivergenceRowsShown)
				break
			}
			cut := ""
			if o.Truncated {
				cut = " (values cut for display)"
			}
			fmt.Fprintf(b, "  - %s: baseline %s; candidate %s%s\n", inline(o.Key), observedValue(o.Base, o.BaseRecorded), observedValue(o.Candidate, o.CandidateRecorded), cut)
		}
	}
	fmt.Fprintf(b, "\n%s\n", inline(model.DivergenceNote))
}

// observedValue renders one side of a divergence row. The markers are written
// unescaped, so a recorded value (always escaped) cannot produce them.
func observedValue(v string, recorded bool) string {
	switch {
	case !recorded:
		return "(not recorded)"
	case v == "":
		return "(empty)"
	}
	return inline(v)
}

// evidenceCheckLine names the checks an evidence record rests on, or returns
// "" when it cites none.
func evidenceCheckLine(e model.Evidence) string {
	if e.CheckID == "" {
		return ""
	}
	var s string
	switch e.Kind {
	case model.EvidenceIntentTest:
		s = fmt.Sprintf("Candidate check: %s (candidate-only; no baseline control)", inline(e.CheckID))
	case model.EvidenceBaseTestDifferential:
		s = fmt.Sprintf("Hybrid-tree check: %s; baseline check: %s", inline(e.CheckID), inline(e.BaseCheckID))
	default:
		s = fmt.Sprintf("Candidate check: %s; baseline check: %s", inline(e.CheckID), inline(e.BaseCheckID))
	}
	if e.RepeatCheckID != "" {
		s += "; baseline repeat: " + inline(e.RepeatCheckID)
	}
	return s
}

// Attribution is the notice that identifies SwiftProof in generated reports.
func Attribution(version string) string {
	if version == "" {
		return "Generated by SwiftProof (https://github.com/gvinsot/SwiftProof)."
	}
	return fmt.Sprintf("Generated by SwiftProof %s (https://github.com/gvinsot/SwiftProof).", inline(version))
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

// Write replaces each report atomically. It validates every format, sanitizes
// the report once and renders every requested format into memory before it
// touches disk, so a validation or render error writes nothing. Callers run
// Finalize first.
func Write(dir string, r *model.Report, formats []string, opts ...Option) error {
	if len(formats) == 0 {
		formats = []string{FormatMarkdown, FormatJSON}
	}
	for _, format := range formats {
		if !ValidFormat(format) {
			return fmt.Errorf("unsupported report format %q", format)
		}
	}
	var o writeOptions
	for _, opt := range opts {
		if opt != nil {
			opt(&o)
		}
	}
	safe := Sanitize(r)
	type rendered struct {
		name string
		data []byte
	}
	var files []rendered
	for _, format := range unique(formats) {
		name, data, err := renderFormat(format, safe, o)
		if err != nil {
			return err
		}
		files = append(files, rendered{name, data})
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	for _, f := range files {
		if err := atomicWrite(filepath.Join(dir, f.name), f.data); err != nil {
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
			v.SetString(redact.Redact(v.String()))
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
