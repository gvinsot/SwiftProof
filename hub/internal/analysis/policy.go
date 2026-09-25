package analysis

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Languages the CLI can seed a policy for.
var Languages = []string{"go", "typescript", "javascript", "python", "unknown"}

// SupportedLanguage reports whether the CLI accepts a language name.
func SupportedLanguage(language string) bool {
	for _, l := range Languages {
		if l == language {
			return true
		}
	}
	return false
}

// Policy renders the default policy for a language by asking the installed
// CLI to generate it. Deriving it from the binary that will run the analysis
// keeps the committed file in step with the tool, instead of freezing a copy
// of its defaults inside the hub.
func (r *Runner) Policy(ctx context.Context, language string) ([]byte, error) {
	if !SupportedLanguage(language) {
		return nil, fmt.Errorf("unsupported language %q", language)
	}
	dir, err := os.MkdirTemp("", "swiftproof-policy-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, r.cfg.Binary, "init", "--repo", dir, "--language", language)
	cmd.Env = cliEnv(dir)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("swiftproof init: %w: %s", err, tail(out.String()))
	}
	data, err := os.ReadFile(filepath.Join(dir, ".swiftproof.json"))
	if err != nil {
		return nil, fmt.Errorf("swiftproof init produced no policy: %w", err)
	}
	// Re-encode so the committed file is stable and indented the same way
	// whatever the CLI version formatting.
	var value any
	if err := json.Unmarshal(data, &value); err != nil {
		return nil, fmt.Errorf("generated policy is not valid JSON: %w", err)
	}
	pretty, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(pretty, '\n'), nil
}

// Version reports the CLI version the hub runs, shown in the UI so a user can
// tell which tool produced a report.
func (r *Runner) Version(ctx context.Context) string {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, r.cfg.Binary, "version").Output()
	if err != nil {
		return "unknown"
	}
	line := strings.TrimSpace(strings.SplitN(string(out), "\n", 2)[0])
	return strings.TrimSpace(strings.TrimPrefix(line, "swiftproof"))
}
