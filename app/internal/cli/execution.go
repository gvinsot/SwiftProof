package cli

// F0 stub of the execution cache and summary (F7a owns this file). No cache is
// ever used without an explicit --cache-dir, and the stub refuses one before
// any container starts.

import (
	"context"
	"errors"
	"io"

	"github.com/gvinsot/SwiftProof/app/internal/harness"
	"github.com/gvinsot/SwiftProof/app/internal/model"
)

// openExecutionCache validates --cache-dir (location, ownership, symlinks) and
// opens the cache. It returns nil, nil when cacheDir is "" and makes no Docker
// call. Its error exits 3. The stub refuses every directory.
func openExecutionCache(repoRoot, outputDir, cacheDir, version string, errOut io.Writer) (harness.ExecutionCache, error) {
	if cacheDir == "" {
		return nil, nil
	}
	return nil, errors.New("the execution cache is not implemented in this build")
}

// initialChecks returns the configured initial check kinds in their fixed
// order: test, typecheck, build.
func initialChecks(commands map[string][]string) []string {
	var kinds []string
	for _, kind := range []string{"test", "typecheck", "build"} {
		if _, ok := commands[kind]; ok {
			kinds = append(kinds, kind)
		}
	}
	return kinds
}

// executionSummary returns the report's execution object (cache, parallelism,
// budget); nil when no harness ran. The stub returns nil.
func executionSummary(h *harness.Harness, work context.Context) *model.Execution { return nil }

// executionLine is the stdout line of the execution summary; the stub prints none.
func executionLine(e *model.Execution) string { return "" }
