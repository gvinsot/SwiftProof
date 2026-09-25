package harness

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/gvinsot/SwiftProof/app/internal/model"
)

// ResultsBudget bounds the total size of Check.Results over both check ledgers
// of one harness (one report). A capture whose normalized results would exceed
// what remains follows its consumer's overflow rule: the results are kept only
// as a hashed artifact, never silently dropped or cut.
const ResultsBudget = 16 << 20

// stageEphemeral writes content at rel under root with O_EXCL, creating missing
// directories; cleanup removes the file then the directories it created, deepest first.
//
// rel is validated like every tool path (no escape, no symlink component, no
// secret-bearing name), and an existing file is never overwritten. The returned
// cleanup is never nil and is safe to call more than once; on error nothing
// stays behind and the cleanup does nothing.
func stageEphemeral(root, rel, content string) (cleanup func(), err error) {
	noop := func() {}
	if root == "" {
		return noop, errors.New("no snapshot to stage into")
	}
	root = filepath.Clean(root)
	path, err := safePath(root, rel)
	if err != nil {
		return noop, err
	}
	var created []string // missing directories, deepest first
	for dir := filepath.Dir(path); dir != root && len(dir) > len(root); dir = filepath.Dir(dir) {
		if _, e := os.Lstat(dir); e == nil {
			break
		} else if !os.IsNotExist(e) {
			return noop, e
		}
		created = append(created, dir)
	}
	removeDirs := func() {
		for _, dir := range created {
			_ = os.Remove(dir)
		}
	}
	if err = os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		removeDirs()
		return noop, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		removeDirs()
		return noop, err
	}
	_, writeErr := f.WriteString(content)
	closeErr := f.Close()
	var once sync.Once
	cleanup = func() {
		once.Do(func() {
			_ = os.Remove(path)
			removeDirs()
		})
	}
	if writeErr != nil {
		cleanup()
		return noop, writeErr
	}
	if closeErr != nil {
		cleanup()
		return noop, closeErr
	}
	return cleanup, nil
}

// privateCopy copies the sanitized candidate snapshot into a new directory under h.root
// (os.MkdirTemp(h.root, prefix) + copySnapshot). Caller holds h.mu.
//
// The copy is a private workspace for a stage that must modify candidate files
// (a hybrid tree, a mutant). It never aliases h.candidate, and Close removes it
// with the rest of h.root if the caller does not.
func (h *Harness) privateCopy(prefix string) (dir string, cleanup func(), err error) {
	noop := func() {}
	if h.closed {
		return "", noop, errors.New("harness is closed")
	}
	if prefix == "" || strings.ContainsAny(prefix, `/\:`) || strings.Contains(prefix, "..") {
		return "", noop, fmt.Errorf("invalid private copy prefix %q", prefix)
	}
	dir, err = os.MkdirTemp(h.root, prefix)
	if err != nil {
		return "", noop, err
	}
	var once sync.Once
	cleanup = func() { once.Do(func() { _ = os.RemoveAll(dir) }) }
	if err = copySnapshot(h.candidate, dir); err != nil {
		cleanup()
		return "", noop, fmt.Errorf("private candidate copy: %w", err)
	}
	return dir, cleanup, nil
}

// appendEvidence assigns "evidence-N", copies slices and appends. Caller holds h.mu.
// It returns the record as stored. Every harness path that creates evidence
// goes through it, so IDs stay unique and dense across features.
func (h *Harness) appendEvidence(e model.Evidence) model.Evidence {
	e.ID = fmt.Sprintf("evidence-%d", len(h.evidence)+1)
	e.TestNames = append([]string(nil), e.TestNames...)
	e.ReferencedSymbols = append([]string(nil), e.ReferencedSymbols...)
	h.evidence = append(h.evidence, e)
	stored := e
	stored.TestNames = append([]string(nil), e.TestNames...)
	stored.ReferencedSymbols = append([]string(nil), e.ReferencedSymbols...)
	return stored
}

// replaceCheck replaces the check with c.ID in the ledger its ID prefix names. Caller holds h.mu.
//
// "mutation-check-N" names the mutation ledger and "check-N" the main one. A
// check whose ID is not recorded is ignored: replacement never adds a check.
// The results budget follows the replacement, so h.resultsBytes always equals
// the total size of Check.Results over both ledgers.
func (h *Harness) replaceCheck(c model.Check) {
	ledger := &h.checks
	if strings.HasPrefix(c.ID, mutationCheckPrefix) {
		ledger = &h.mutationChecks
	} else if !strings.HasPrefix(c.ID, checkPrefix) {
		return
	}
	for i := len(*ledger) - 1; i >= 0; i-- {
		if (*ledger)[i].ID == c.ID {
			h.resultsBytes += len(c.Results) - len((*ledger)[i].Results)
			(*ledger)[i] = c
			return
		}
	}
}

// copyChecks deep-copies a ledger: Command and Cache are never shared with the
// caller.
func copyChecks(ledger []model.Check) []model.Check {
	checks := append([]model.Check(nil), ledger...)
	for i := range checks {
		checks[i].Command = append([]string(nil), checks[i].Command...)
		if checks[i].Cache != nil {
			cache := *checks[i].Cache
			checks[i].Cache = &cache
		}
	}
	return checks
}

// resultsRemaining is what is left of ResultsBudget. Caller holds h.mu.
func (h *Harness) resultsRemaining() int {
	return ResultsBudget - h.resultsBytes
}

// baselineSideKind reports whether kind is a baseline-side run: a kind ending
// in "_base", or one of the baseline re-run kinds generated_test_base_repeat
// and fuzz_base_confirm. Candidate code never writes what such a run returns.
func baselineSideKind(kind string) bool {
	return strings.HasSuffix(kind, "_base") || kind == model.CheckGeneratedBaseRepeat || kind == model.CheckFuzzBaseConfirm
}

// resultsRemainingFor is what a run of this kind may still add to
// Check.Results. The results of every other kind, which candidate code can
// write, share at most half of ResultsBudget, so they can never use up the half
// that baseline-side captures rely on: an over-budget baseline capture is then
// caused by baseline-side output alone. Every capture that records Results
// checks this, not resultsRemaining. Caller holds h.mu.
func (h *Harness) resultsRemainingFor(kind string) int {
	remaining := h.resultsRemaining()
	if baselineSideKind(kind) {
		return remaining
	}
	candidate := 0
	for _, ledger := range [][]model.Check{h.checks, h.mutationChecks} {
		for _, c := range ledger {
			if !baselineSideKind(c.Kind) {
				candidate += len(c.Results)
			}
		}
	}
	if share := ResultsBudget/2 - candidate; share < remaining {
		remaining = share
	}
	return remaining
}

// PayloadLimit derives the per-run payload budget from trusted policy rather
// than introducing an unconfigurable host buffer: 16 × max_output_bytes,
// bounded to [256 KiB, 4 MiB]. A real coverage profile runs to hundreds of
// kilobytes, far beyond a log budget.
func PayloadLimit(maxOutputBytes int) int {
	limit := 16 * maxOutputBytes
	if limit < 256*1024 {
		limit = 256 * 1024
	}
	if limit > 4*1024*1024 {
		limit = 4 * 1024 * 1024
	}
	return limit
}

// VerifiableGoTemplate reports whether a configured go test template can
// establish that named tests ran from one injected package: `go test` with
// exactly one standalone {package} or {file} target and only flags otherwise,
// with no working-directory change, overlay, exec wrapper or argument
// pass-through.
func VerifiableGoTemplate(cmd []string) bool { return verifiableGoTemplate(cmd) }
