// Package analysis fetches a pushed commit and runs the SwiftProof CLI on it.
//
// The hub never becomes a second implementation of the review: it prepares a
// disposable checkout, executes the trusted binary, and stores the confidence
// report the CLI produced. In the default lint mode no repository code is
// executed at all; review mode runs the configured checks in the CLI's own
// Docker sandbox and therefore requires a deliberately mounted Docker socket.
package analysis

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/gvinsot/SwiftProof/hub/internal/accounts"
	"github.com/gvinsot/SwiftProof/hub/internal/config"
	"github.com/gvinsot/SwiftProof/hub/internal/events"
	"github.com/gvinsot/SwiftProof/hub/internal/forge"
	"github.com/gvinsot/SwiftProof/hub/internal/report"
	"github.com/gvinsot/SwiftProof/hub/internal/store"
)

// reportPath is where the CLI writes the machine-readable report.
const reportPath = ".swiftproof/confidence-report.json"

// maxReportBytes bounds the report read back from the sandbox output.
const maxReportBytes = 64 << 20

// maxOutputBytes bounds the CLI output kept for diagnostics.
const maxOutputBytes = 16 << 10

// Triggers recorded on a run.
const (
	TriggerPush   = "push"
	TriggerManual = "manual"
)

var commitPattern = regexp.MustCompile(`^[0-9a-f]{7,64}$`)

// Job is one analysis request.
type Job struct {
	UserKey string
	RepoKey string
	Commit  string
	Before  string
	Ref     string
	Message string
	Author  string
	Trigger string
}

// ErrBusy is returned when the queue is saturated; the caller should retry.
var ErrBusy = errors.New("analysis queue is full")

// Runner owns the worker pool and the analysis pipeline.
type Runner struct {
	cfg      config.Config
	store    *store.Store
	accounts *accounts.Manager
	events   *events.Broker
	log      *slog.Logger
	queue    chan Job
	mu       sync.Mutex
	active   map[string]struct{}
}

// New builds a runner. Start must be called to process jobs.
func New(cfg config.Config, s *store.Store, a *accounts.Manager, b *events.Broker, log *slog.Logger) *Runner {
	return &Runner{
		cfg: cfg, store: s, accounts: a, events: b, log: log,
		queue:  make(chan Job, cfg.QueueSize),
		active: map[string]struct{}{},
	}
}

// Start launches the workers and returns immediately.
func (r *Runner) Start(ctx context.Context) {
	for i := 0; i < r.cfg.Workers; i++ {
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case job := <-r.queue:
					r.process(ctx, job)
					r.release(job)
				}
			}
		}()
	}
}

func jobKey(j Job) string { return j.UserKey + "/" + j.RepoKey + "/" + j.Commit }

// Enqueue schedules an analysis, ignoring a commit already queued or running.
func (r *Runner) Enqueue(j Job) error {
	if !commitPattern.MatchString(j.Commit) {
		return fmt.Errorf("invalid commit %q", j.Commit)
	}
	r.mu.Lock()
	if _, busy := r.active[jobKey(j)]; busy {
		r.mu.Unlock()
		return nil
	}
	r.active[jobKey(j)] = struct{}{}
	r.mu.Unlock()
	select {
	case r.queue <- j:
		r.markQueued(j)
		return nil
	default:
		r.release(j)
		return ErrBusy
	}
}

func (r *Runner) release(j Job) {
	r.mu.Lock()
	delete(r.active, jobKey(j))
	r.mu.Unlock()
}

// Pending reports the queue depth, for the health endpoint.
func (r *Runner) Pending() int { return len(r.queue) }

func (r *Runner) markQueued(j Job) {
	run := store.Run{
		Commit: j.Commit, BaseCommit: j.Before, Ref: j.Ref, Message: firstLine(j.Message),
		Author: j.Author, Status: store.StatusQueued, Trigger: j.Trigger, QueuedAt: time.Now().UTC(),
	}
	r.publishRun(j, run)
}

// publishRun stores the run as the repository's latest state and streams it.
func (r *Runner) publishRun(j Job, run store.Run) {
	repo, err := r.store.UpdateRepo(j.UserKey, j.RepoKey, func(repo *store.Repo) error {
		// A late finish of an older commit must not overwrite a newer run.
		if repo.Latest != nil && repo.Latest.Commit != run.Commit && repo.Latest.QueuedAt.After(run.QueuedAt) {
			return nil
		}
		repo.Latest = &run
		return nil
	})
	if err != nil {
		r.log.Error("store run", "repo", j.RepoKey, "error", err)
		return
	}
	r.events.Publish(j.UserKey, map[string]any{"type": "repo", "repo": repo.Public()})
}

func (r *Runner) process(ctx context.Context, j Job) {
	started := time.Now().UTC()
	run := store.Run{
		Commit: j.Commit, BaseCommit: j.Before, Ref: j.Ref, Message: firstLine(j.Message),
		Author: j.Author, Status: store.StatusRunning, Trigger: j.Trigger,
		QueuedAt: started, StartedAt: started,
	}
	r.publishRun(j, run)

	ctx, cancel := context.WithTimeout(ctx, r.cfg.AnalysisTimeout)
	defer cancel()

	rec, err := r.analyze(ctx, j, &run)
	run.FinishedAt = time.Now().UTC()
	run.DurationMS = run.FinishedAt.Sub(started).Milliseconds()
	if err != nil {
		run.Status = store.StatusFailed
		run.Error = err.Error()
		r.log.Error("analysis failed", "repo", j.RepoKey, "commit", short(j.Commit), "error", err)
	} else {
		run.Status = store.StatusDone
	}
	if rec != nil {
		rec.Run = run
		if err := r.store.PutRecord(rec); err != nil {
			r.log.Error("store report", "repo", j.RepoKey, "error", err)
		}
	}
	r.publishRun(j, run)
	if rec != nil {
		r.events.Publish(j.UserKey, map[string]any{
			"type": "report", "repo_key": j.RepoKey, "commit": j.Commit, "run": run,
		})
	}
	r.publishStatus(ctx, j, run)
}

// analyze does the work and returns the stored record when a report exists.
func (r *Runner) analyze(ctx context.Context, j Job, run *store.Run) (*store.Record, error) {
	repo, err := r.store.Repo(j.UserKey, j.RepoKey)
	if err != nil {
		return nil, fmt.Errorf("repository: %w", err)
	}
	user, err := r.store.User(j.UserKey)
	if err != nil {
		return nil, fmt.Errorf("account: %w", err)
	}
	provider, err := r.accounts.Provider(repo.Provider)
	if err != nil {
		return nil, err
	}
	token, err := r.accounts.Token(ctx, user)
	if err != nil {
		return nil, err
	}

	work, err := os.MkdirTemp("", "swiftproof-hub-")
	if err != nil {
		return nil, fmt.Errorf("workspace: %w", err)
	}
	defer os.RemoveAll(work)

	g := &gitRunner{dir: work, env: gitEnv(work, repo.CloneURL, provider.GitAuthHeader(token))}
	if err := g.prepare(ctx, repo.CloneURL); err != nil {
		return nil, err
	}
	branch := strings.TrimPrefix(j.Ref, "refs/heads/")
	if branch == "" {
		branch = repo.DefaultBranch
	}
	if err := g.fetch(ctx, branch, j.Commit, r.cfg.CloneDepth); err != nil {
		return nil, err
	}
	if _, err := g.run(ctx, "checkout", "--detach", j.Commit); err != nil {
		return nil, err
	}
	base := g.resolveBase(ctx, j.Before, j.Commit, r.cfg.CloneDepth)
	run.BaseCommit = base

	output, exitCode, runErr := r.runCLI(ctx, work, base, j.Commit)
	data, readErr := readBounded(filepath.Join(work, reportPath), maxReportBytes)
	if readErr != nil {
		if runErr != nil {
			return nil, fmt.Errorf("swiftproof %s exited %d: %s", r.cfg.Mode, exitCode, tail(output))
		}
		return nil, fmt.Errorf("no confidence report was produced: %w", readErr)
	}
	parsed, err := report.Decode(data)
	if err != nil {
		return nil, err
	}
	summary := parsed.Summarize()
	run.Summary = summary
	run.ToolVersion = parsed.ToolVersion
	// Exit codes 0, 1 and 2 are review outcomes, not failures; 3 and 4 mean
	// the run itself could not be completed and the report is incomplete.
	if exitCode >= 3 {
		return &store.Record{
			UserKey: j.UserKey, RepoKey: j.RepoKey, RepoName: repo.FullName, Raw: json.RawMessage(data),
		}, fmt.Errorf("swiftproof %s could not complete (exit %d): %s", r.cfg.Mode, exitCode, tail(output))
	}
	return &store.Record{
		UserKey: j.UserKey, RepoKey: j.RepoKey, RepoName: repo.FullName, Raw: json.RawMessage(data),
	}, nil
}

// runCLI executes the trusted binary on the prepared checkout.
func (r *Runner) runCLI(ctx context.Context, work, base, head string) (string, int, error) {
	args := []string{
		r.cfg.Mode,
		"--repo", work,
		"--base", base,
		"--head", head,
		"--exact",
		"--format", "json,markdown",
		"--out", ".swiftproof",
		"--ci",
	}
	if r.cfg.Mode == config.ModeReview {
		// The hub holds no provider credential of its own: LLM investigation
		// stays a deployment decision made through the CLI's own environment.
		if os.Getenv(config.EndpointEnvName) == "" {
			args = append(args, "--reviewer=false")
		}
	}
	cmd := exec.CommandContext(ctx, r.cfg.Binary, args...)
	cmd.Dir = work
	cmd.Env = cliEnv(work)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	exitCode := 0
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		exitCode = exitErr.ExitCode()
	} else if err != nil {
		return out.String(), -1, fmt.Errorf("run %s: %w", r.cfg.Binary, err)
	}
	return out.String(), exitCode, err
}

// publishStatus reports the outcome back onto the commit, when enabled.
func (r *Runner) publishStatus(ctx context.Context, j Job, run store.Run) {
	if !r.cfg.CommitStatus {
		return
	}
	repo, err := r.store.Repo(j.UserKey, j.RepoKey)
	if err != nil || !repo.Monitored {
		return
	}
	user, err := r.store.User(j.UserKey)
	if err != nil {
		return
	}
	provider, err := r.accounts.Provider(repo.Provider)
	if err != nil {
		return
	}
	token, err := r.accounts.Token(ctx, user)
	if err != nil {
		return
	}
	state, description := forge.StateSuccess, statusDescription(run)
	switch {
	case run.Status == store.StatusFailed:
		state = forge.StateError
	case run.Summary.ExitCode == 1:
		state = forge.StateFailure
	case run.Summary.ExitCode == 2:
		// A human decision is required, which is exactly what a failed status
		// asks for; the hub never auto-approves.
		state = forge.StateFailure
	}
	target := r.cfg.BaseURL + "/app.html#/repo/" + repo.Key + "/commit/" + run.Commit
	// The status is best effort: a missing scope must not fail the analysis.
	if err := provider.SetStatus(ctx, token, forge.Repo{ID: repo.ID, FullName: repo.FullName}, run.Commit, state, description, target); err != nil {
		r.log.Warn("commit status", "repo", repo.FullName, "error", err)
	}
}

func statusDescription(run store.Run) string {
	if run.Status == store.StatusFailed {
		return "SwiftProof could not complete this analysis"
	}
	c := run.Summary.Counts
	switch run.Summary.Verdict {
	case report.VerdictBlocked:
		return fmt.Sprintf("%d reproduced issue(s); %d high or critical alert(s)", run.Summary.Reproduced, c.AtLeast(report.SeverityHigh))
	case report.VerdictReview:
		return fmt.Sprintf("Human review required: %d alert(s), %d focused of %d changed lines", c.Total, run.Summary.FocusedLines, run.Summary.ChangedLines)
	default:
		return fmt.Sprintf("No reproduced blocker; %d alert(s) recorded", c.Total)
	}
}

// cliEnv gives the CLI a minimal environment. Docker and provider settings are
// forwarded so an operator can enable review mode without patching the image.
func cliEnv(work string) []string {
	env := []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + work,
		"TMPDIR=" + filepath.Join(work, "tmp"),
		"GIT_TERMINAL_PROMPT=0",
		"GIT_CONFIG_NOSYSTEM=1",
	}
	for _, name := range []string{"DOCKER_HOST", "DOCKER_CERT_PATH", "DOCKER_TLS_VERIFY", config.EndpointEnvName, config.ModelEnvName, "SWIFTPROOF_API_KEY"} {
		if v := os.Getenv(name); v != "" {
			env = append(env, name+"="+v)
		}
	}
	_ = os.MkdirAll(filepath.Join(work, "tmp"), 0o700)
	return env
}

func readBounded(path string, max int64) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Size() > max {
		return nil, fmt.Errorf("confidence report exceeds %d bytes", max)
	}
	return os.ReadFile(path)
}

func tail(output string) string {
	output = strings.TrimSpace(output)
	if len(output) > maxOutputBytes {
		output = "…" + output[len(output)-maxOutputBytes:]
	}
	return output
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	if len(s) > 200 {
		s = s[:199] + "…"
	}
	return s
}

func short(commit string) string {
	if len(commit) > 12 {
		return commit[:12]
	}
	return commit
}
