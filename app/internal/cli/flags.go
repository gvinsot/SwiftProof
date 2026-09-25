package cli

import (
	"flag"
	"fmt"
	"strings"
	"time"
)

// Bounds of the v0.4 execution flags (contract §1.6).
const (
	maxParallel     = 4
	maxCacheDirLen  = 4096
	minDeadline     = time.Minute
	maxDeadline     = 24 * time.Hour
	deadlineReserve = 30 * time.Second // kept for cleanup and report writing
)

// executionOnlyFlags are the v0.4 flags that only make sense when sandbox checks
// run. Setting one explicitly on lint is an error, whatever its value.
var executionOnlyFlags = []string{"base-tests", "fuzz", "impacted-tests", "cache-dir", "parallel", "allow-prepare-network", "deadline"}

// execFlags carries the values validateExecutionFlags checks.
type execFlags struct {
	checks, baseTests, impact, impactedTests bool
	parallel                                 int
	cacheDir                                 string
	deadline                                 time.Duration
}

// visitedFlags returns the names of the flags set on the command line (flag.Visit),
// which is what "explicit" means for every flag rule.
func visitedFlags(f *flag.FlagSet) map[string]bool {
	explicit := map[string]bool{}
	f.Visit(func(option *flag.Flag) { explicit[option.Name] = true })
	return explicit
}

// validateExecutionFlags applies the §1.6 rules. It runs before any repository
// access and before any container starts; every error exits 3. The cache
// directory's location and ownership are checked later, by openExecutionCache,
// which also runs before any container.
func validateExecutionFlags(mode string, explicit map[string]bool, v execFlags) error {
	if mode == "lint" {
		for _, name := range executionOnlyFlags {
			if explicit[name] {
				return fmt.Errorf("lint does not execute sandbox checks; --%s applies to review only", name)
			}
		}
	}
	if v.parallel < 1 || v.parallel > maxParallel {
		return fmt.Errorf("--parallel must be between 1 and %d", maxParallel)
	}
	if explicit["deadline"] || v.deadline != 0 {
		if v.deadline < minDeadline || v.deadline > maxDeadline {
			return fmt.Errorf("--deadline must be a duration between %s and %s", "1m", "24h")
		}
	}
	if explicit["cache-dir"] || v.cacheDir != "" {
		if strings.TrimSpace(v.cacheDir) == "" {
			return fmt.Errorf("--cache-dir must name a directory")
		}
		if len(v.cacheDir) > maxCacheDirLen || strings.ContainsRune(v.cacheDir, 0) {
			return fmt.Errorf("--cache-dir must be at most %d bytes without NUL", maxCacheDirLen)
		}
	}
	if v.baseTests && !v.checks {
		return fmt.Errorf("--base-tests runs baseline versions of changed tests as checks; it cannot be combined with --checks=false")
	}
	if v.impactedTests && !v.checks {
		return fmt.Errorf("--impacted-tests runs existing tests as checks; it cannot be combined with --checks=false")
	}
	if v.impactedTests && !v.impact {
		return fmt.Errorf("--impacted-tests selects tests from the impact index; it cannot be combined with --impact=false")
	}
	return nil
}
