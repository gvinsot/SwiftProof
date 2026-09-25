package config

import (
	"fmt"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/gvinsot/SwiftProof/app/internal/coverage"
)

// Prepare users, defaults and limits.
const (
	PrepareUserSandbox           = "sandbox"
	PrepareUserRoot              = "root"
	DefaultPrepareTimeoutSeconds = 600
	DefaultPrepareMaxAddedMB     = 4096
	MaxPrepareInputs             = 64
	MaxPrepareEnv                = 32
)

// Prepare lets the trusted base-branch policy derive the sandbox image by
// running one command on dependency inputs exported from the base commit. It is
// opt-in and release-ordered like Fuzz. It is not a command key: the harness can
// never run it on the candidate.
type Prepare struct {
	Command        []string          `json:"command"`
	Inputs         []string          `json:"inputs"`
	Network        bool              `json:"network"`
	User           string            `json:"user,omitempty"`            // "" means sandbox
	TimeoutSeconds int               `json:"timeout_seconds,omitempty"` // 0 means 600
	Env            map[string]string `json:"env,omitempty"`             // baked into the derived image
	MaxAddedMB     int               `json:"max_added_mb,omitempty"`    // 0 means 4096
}

var prepareEnvName = regexp.MustCompile(`^[A-Z_][A-Z0-9_]{0,63}$`)

// prepareReservedEnv are the variables the checks themselves set or override.
var prepareReservedEnv = map[string]bool{
	"HOME": true, "TMPDIR": true, "GOCACHE": true, "GOTOOLCHAIN": true, "GOPROXY": true, "GOSUMDB": true,
}

// validate is nil-safe: a nil receiver means preparation is not configured.
// Credential-bearing input matches are refused later, at export time, by the
// prepare package.
func (p *Prepare) validate(s Sandbox) error {
	if p == nil {
		return nil
	}
	if len(p.Command) == 0 || len(p.Command) > 128 || strings.TrimSpace(p.Command[0]) == "" {
		return fmt.Errorf("prepare.command must be a nonempty argv array (at most 128 arguments)")
	}
	for _, arg := range p.Command {
		if strings.ContainsRune(arg, 0) || len(arg) > 16384 {
			return fmt.Errorf("invalid argument in prepare.command")
		}
		for _, token := range []string{"{file}", PackagePlaceholder, coverage.Placeholder, ResultsPlaceholder} {
			if strings.Contains(arg, token) {
				return fmt.Errorf("prepare.command does not substitute placeholders; remove %s", token)
			}
		}
	}
	if len(p.Inputs) == 0 || len(p.Inputs) > MaxPrepareInputs {
		return fmt.Errorf("prepare.inputs must list between 1 and %d path patterns", MaxPrepareInputs)
	}
	for _, pattern := range p.Inputs {
		if err := validatePrepareInput(pattern); err != nil {
			return err
		}
	}
	switch p.User {
	case "", PrepareUserSandbox, PrepareUserRoot:
	default:
		return fmt.Errorf("prepare.user must be %q or %q", PrepareUserSandbox, PrepareUserRoot)
	}
	if p.TimeoutSeconds < 0 || p.TimeoutSeconds > 3600 {
		return fmt.Errorf("prepare.timeout_seconds must be 0 (600 seconds) or between 1 and 3600")
	}
	if len(p.Env) > MaxPrepareEnv {
		return fmt.Errorf("prepare.env may set at most %d variables", MaxPrepareEnv)
	}
	for name, value := range p.Env {
		if !prepareEnvName.MatchString(name) {
			return fmt.Errorf("prepare.env name %q must match %s", name, prepareEnvName.String())
		}
		if prepareReservedEnv[name] || strings.HasPrefix(name, "SWIFTPROOF_") {
			return fmt.Errorf("prepare.env must not set %s: checks set or override it", name)
		}
		if len(value) > 4096 || strings.ContainsAny(value, "\x00\r\n") {
			return fmt.Errorf("prepare.env value of %s must be at most 4096 bytes on one line without NUL", name)
		}
	}
	if p.MaxAddedMB < 0 || p.MaxAddedMB > 65536 {
		return fmt.Errorf("prepare.max_added_mb must be 0 (4096) or between 1 and 65536")
	}
	return nil
}

// validatePrepareInput accepts a repository-relative path.Match pattern that
// cannot escape the tree, reach .git or recurse.
func validatePrepareInput(pattern string) error {
	if pattern == "" || len(pattern) > 512 || strings.ContainsRune(pattern, 0) {
		return fmt.Errorf("prepare.inputs patterns must be 1 to 512 bytes without NUL")
	}
	if strings.Contains(pattern, "\\") {
		return fmt.Errorf("prepare.inputs pattern %q must use forward slashes", pattern)
	}
	if strings.HasPrefix(pattern, "/") || strings.HasPrefix(pattern, "./") {
		return fmt.Errorf("prepare.inputs pattern %q must be relative to the repository root without a leading / or ./", pattern)
	}
	if strings.Contains(pattern, "**") {
		return fmt.Errorf("prepare.inputs pattern %q: recursive globs (**) are not supported", pattern)
	}
	for _, segment := range strings.Split(pattern, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return fmt.Errorf("prepare.inputs pattern %q has an empty, . or .. segment", pattern)
		}
		if strings.EqualFold(segment, ".git") {
			return fmt.Errorf("prepare.inputs pattern %q must not reach .git", pattern)
		}
	}
	if _, err := path.Match(pattern, ""); err != nil {
		return fmt.Errorf("invalid prepare.inputs pattern %q: %w", pattern, err)
	}
	return nil
}

// EffectiveUser returns the container identity: "" means sandbox.
func (p *Prepare) EffectiveUser() string {
	if p == nil || p.User == "" {
		return PrepareUserSandbox
	}
	return p.User
}

// EffectiveTimeout returns the prepare time limit: 0 means 600 seconds.
func (p *Prepare) EffectiveTimeout() time.Duration {
	if p == nil || p.TimeoutSeconds == 0 {
		return DefaultPrepareTimeoutSeconds * time.Second
	}
	return time.Duration(p.TimeoutSeconds) * time.Second
}

// EffectiveMaxAddedMB returns how many MiB the derived image may add to the
// base image: 0 means 4096.
func (p *Prepare) EffectiveMaxAddedMB() int {
	if p == nil || p.MaxAddedMB == 0 {
		return DefaultPrepareMaxAddedMB
	}
	return p.MaxAddedMB
}
