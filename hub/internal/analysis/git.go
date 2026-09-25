package analysis

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// gitRunner drives git in a disposable directory with a minimal environment.
type gitRunner struct {
	dir string
	env []string
}

// gitEnv builds the environment of every git invocation.
//
// The credential is injected through GIT_CONFIG_* variables scoped to the
// remote URL: it never appears on the command line, where it would be visible
// in the process table, and it is never sent to another host.
func gitEnv(home, cloneURL, authHeader string) []string {
	env := []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + home,
		"GIT_TERMINAL_PROMPT=0",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_CONFIG_SYSTEM=/dev/null",
		"GIT_ASKPASS=/bin/true",
		"LC_ALL=C",
	}
	if authHeader == "" || cloneURL == "" {
		return env
	}
	return append(env,
		"GIT_CONFIG_COUNT=1",
		"GIT_CONFIG_KEY_0=http."+cloneURL+".extraheader",
		"GIT_CONFIG_VALUE_0=Authorization: "+authHeader,
	)
}

// run executes one git command and returns its trimmed standard output.
func (g *gitRunner) run(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = g.dir
	cmd.Env = g.env
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return stdout.String(), fmt.Errorf("git %s: %w: %s", args[0], err, tail(stderr.String()))
	}
	return strings.TrimSpace(stdout.String()), nil
}

// prepare initializes an empty repository pointed at the remote.
func (g *gitRunner) prepare(ctx context.Context, cloneURL string) error {
	if cloneURL == "" {
		return fmt.Errorf("repository has no HTTPS clone URL")
	}
	if !strings.HasPrefix(cloneURL, "https://") && !strings.HasPrefix(cloneURL, "http://") {
		return fmt.Errorf("unsupported clone URL scheme")
	}
	if _, err := g.run(ctx, "init", "--quiet", "--initial-branch=swiftproof"); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(g.dir, "tmp"), 0o700); err != nil {
		return err
	}
	_, err := g.run(ctx, "remote", "add", "origin", cloneURL)
	return err
}

// fetch brings in the analyzed commit, preferring the branch ref because every
// server allows it, and falling back to fetching the commit directly when the
// branch has already moved on.
func (g *gitRunner) fetch(ctx context.Context, branch, commit string, depth int) error {
	var branchErr error
	if branch != "" {
		_, branchErr = g.run(ctx, "fetch", "--quiet", "--no-tags",
			fmt.Sprintf("--depth=%d", depth), "origin",
			"+refs/heads/"+branch+":refs/remotes/origin/"+branch)
	}
	if g.has(ctx, commit) {
		return nil
	}
	if _, err := g.run(ctx, "fetch", "--quiet", "--no-tags", fmt.Sprintf("--depth=%d", depth), "origin", commit); err != nil {
		if branchErr != nil {
			return branchErr
		}
		return err
	}
	if !g.has(ctx, commit) {
		return fmt.Errorf("commit %s is not reachable on the remote", short(commit))
	}
	return nil
}

// has reports whether a commit object is present locally.
func (g *gitRunner) has(ctx context.Context, rev string) bool {
	if rev == "" {
		return false
	}
	_, err := g.run(ctx, "cat-file", "-e", rev+"^{commit}")
	return err == nil
}

// resolveBase picks the commit the candidate is compared against: the commit
// the branch pointed at before the push when it is still reachable, the first
// parent otherwise, and the candidate itself for an initial commit, which
// yields an empty, honest range rather than a wrong one.
func (g *gitRunner) resolveBase(ctx context.Context, before, head string, depth int) string {
	if commitPattern.MatchString(before) && strings.Trim(before, "0") != "" {
		if g.has(ctx, before) {
			return before
		}
		if _, err := g.run(ctx, "fetch", "--quiet", "--no-tags", fmt.Sprintf("--depth=%d", depth), "origin", before); err == nil && g.has(ctx, before) {
			return before
		}
	}
	if parent, err := g.run(ctx, "rev-parse", "--verify", "--quiet", head+"^"); err == nil && parent != "" {
		return strings.TrimSpace(parent)
	}
	return head
}
