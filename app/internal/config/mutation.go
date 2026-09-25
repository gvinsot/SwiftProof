package config

import (
	"fmt"
	"path"
	"strings"

	"github.com/gvinsot/SwiftProof/app/internal/coverage"
)

// PackagePlaceholder is the one token a mutation command must contain. It
// expands exactly as in generated_test: "./" plus the repository-relative
// directory of the mutated file, or "." at the root.
const PackagePlaceholder = "{package}"

// Mutation enables mutation of added Go lines. It is opt-in and release-ordered
// like Fuzz. All four fields are required and non-zero, so the reviewed policy
// states its own budget and there are no hidden defaults. max_runtime_seconds is
// a sub-cap inside the shared sandbox runtime budget.
type Mutation struct {
	Command           []string `json:"command"`
	MaxMutants        int      `json:"max_mutants"`
	TimeoutSeconds    int      `json:"timeout_seconds"`
	MaxRuntimeSeconds int      `json:"max_runtime_seconds"`
}

// mutationBannedFlags are the go test flags a mutation command may not set,
// compared after flagName normalization. They change the directory, the
// executed binary or the test selection, or stop the -json stream from being
// the complete record of the package's tests.
var mutationBannedFlags = map[string]bool{
	"args": true, "C": true, "exec": true, "overlay": true, "run": true, "skip": true,
	"list": true, "c": true, "o": true, "fuzz": true, "json": true,
}

// validate is nil-safe: a nil receiver means mutation is not configured.
func (m *Mutation) validate(s Sandbox) error {
	if m == nil {
		return nil
	}
	if len(m.Command) == 0 {
		return fmt.Errorf("mutation.command is required")
	}
	if m.MaxMutants == 0 || m.TimeoutSeconds == 0 || m.MaxRuntimeSeconds == 0 {
		return fmt.Errorf("mutation.max_mutants, mutation.timeout_seconds and mutation.max_runtime_seconds are required and must be non-zero")
	}
	if err := validateMutationCommand(m.Command); err != nil {
		return err
	}
	if m.MaxMutants < 1 || m.MaxMutants > 200 {
		return fmt.Errorf("mutation.max_mutants must be between 1 and 200")
	}
	if m.TimeoutSeconds < 1 || m.TimeoutSeconds > s.TimeoutSeconds {
		return fmt.Errorf("mutation.timeout_seconds must be between 1 and sandbox.timeout_seconds (%d)", s.TimeoutSeconds)
	}
	if m.MaxRuntimeSeconds < m.TimeoutSeconds || m.MaxRuntimeSeconds > s.MaxRuntimeSeconds {
		return fmt.Errorf("mutation.max_runtime_seconds must be between mutation.timeout_seconds (%d) and sandbox.max_runtime_seconds (%d)", m.TimeoutSeconds, s.MaxRuntimeSeconds)
	}
	return nil
}

// validateMutationCommand accepts only a single-package "go test -json" argv
// whose other arguments are self-contained flags (-flag or -flag=value), so the
// executed argv is the reviewed argv plus the {package} expansion.
func validateMutationCommand(argv []string) error {
	if len(argv) < 3 || len(argv) > 128 {
		return fmt.Errorf("mutation.command must have between 3 and 128 arguments")
	}
	for _, arg := range argv {
		if strings.ContainsRune(arg, 0) || len(arg) > 16384 {
			return fmt.Errorf("invalid argument in mutation.command")
		}
	}
	if path.Base(argv[0]) != "go" || argv[1] != "test" {
		return fmt.Errorf("mutation.command must start with \"go\", \"test\"")
	}
	placeholder := func(arg string) error {
		for _, token := range []string{PackagePlaceholder, "{file}", coverage.Placeholder, ResultsPlaceholder} {
			if strings.Contains(arg, token) {
				return fmt.Errorf("mutation.command may contain %s only as one standalone argument and no other placeholder", PackagePlaceholder)
			}
		}
		return nil
	}
	// "{package}/go" passes the path.Base test above: no placeholder may appear
	// anywhere except the one standalone {package} after "test".
	if err := placeholder(argv[0]); err != nil {
		return err
	}
	packages, jsonFlags := 0, 0
	for _, arg := range argv[2:] {
		if arg == PackagePlaceholder {
			packages++
			continue
		}
		if err := placeholder(arg); err != nil {
			return err
		}
		if arg == "-json" {
			jsonFlags++
			continue
		}
		if arg == "--" || !strings.HasPrefix(arg, "-") {
			return fmt.Errorf("mutation.command arguments after \"test\" must be flags written as -flag or -flag=value, plus one %s; got %q", PackagePlaceholder, arg)
		}
		name := flagName(arg)
		if name == "" || mutationBannedFlags[name] || strings.HasPrefix(name, "test.") {
			return fmt.Errorf("mutation.command must not set the go test flag %q", arg)
		}
	}
	if packages != 1 {
		return fmt.Errorf("mutation.command must contain %s exactly once as a standalone argument", PackagePlaceholder)
	}
	if jsonFlags != 1 {
		return fmt.Errorf("mutation.command must contain -json exactly once")
	}
	return nil
}

// flagName strips one or two leading dashes and any "=value", so "--run=x" and
// "-run" compare equal.
func flagName(arg string) string {
	name := strings.TrimPrefix(arg, "-")
	name = strings.TrimPrefix(name, "-")
	if i := strings.IndexByte(name, '='); i >= 0 {
		name = name[:i]
	}
	return name
}
