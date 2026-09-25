// Package cli composes immutable analysis, isolated experiments and evidence reports.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/gvinsot/SwiftProof/app/internal/config"
	"github.com/gvinsot/SwiftProof/app/internal/coverage"
	"github.com/gvinsot/SwiftProof/app/internal/fsutil"
	"github.com/gvinsot/SwiftProof/app/internal/gitrepo"
	"github.com/gvinsot/SwiftProof/app/internal/harness"
	"github.com/gvinsot/SwiftProof/app/internal/linter"
	"github.com/gvinsot/SwiftProof/app/internal/model"
	"github.com/gvinsot/SwiftProof/app/internal/report"
	"github.com/gvinsot/SwiftProof/app/internal/reviewer"
)

const usage = `SwiftProof — evidence for focused review of AI-assisted changes

Usage:
  swiftproof init [--repo PATH] [--language go|typescript|python]
  swiftproof lint [--base main] [--head HEAD] [--ci]
  swiftproof review [--base main] [--reviewer=false] [--ci]
  swiftproof review [flags] BASE..HEAD
  swiftproof report [--input .swiftproof/confidence-report.json] [--out DIR]
  swiftproof version

Analysis compares the merge base by default; BASE..HEAD compares exact commits.
Policy is read from .swiftproof.json at the tip of the base branch (main).
Only committed files are reviewed. Output defaults to .swiftproof/.
Review runs configured checks in Docker. Lint never executes repository code.
Review automatically uses the LLM when reviewer.model is configured in trusted policy.
SWIFTPROOF_REVIEWER_ENDPOINT and SWIFTPROOF_REVIEWER_MODEL override that policy, and
the API key comes from the api_key_env variable or its /run/secrets/<NAME> Docker secret.
The reviewer sends bounded, redacted source context to its configured API.
Use --reviewer=false to disable it. Lint never calls a provider.

Evidence stages (review only unless noted; policy keys fuzz, mutation and prepare
are opt-in and need a v0.4 binary):
  --base-tests             run baseline versions of changed Go tests on candidate code
  --fuzz=false             skip the differential fuzzing that policy "fuzz" configures
  --impact=false           skip the static impact index (lint and review)
  --impacted-tests         run unchanged Go tests that statically reach changed code
  --cache-dir DIR          opt-in baseline execution cache outside repository and output
  --parallel N             run the initial checks N at a time (1..4)
  --allow-prepare-network  permit network for policy "prepare" only if it enables it too
  --deadline D             overall time limit from 1m to 24h (30s are kept for the report)
  --format LIST            report formats: markdown,json (lint, review and report)
  --report-url URL         link to the full report cited by the pr-comment format
Use 'swiftproof <command> --help' for options.
`

func Run(ctx context.Context, args []string, stdout, stderr io.Writer, version string) int {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		fmt.Fprint(stdout, usage)
		return 0
	}
	switch args[0] {
	case "version", "--version":
		fmt.Fprintf(stdout, "swiftproof %s\nAGPL-3.0 with an attribution term, see NOTICE: https://github.com/gvinsot/SwiftProof\n", version)
		return 0
	case "init":
		return initialize(args[1:], stdout, stderr)
	case "lint", "review":
		return analyze(ctx, args[0], args[1:], stdout, stderr, version)
	case "report":
		return render(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown command %q\n%s", args[0], usage)
		return 3
	}
}

func initialize(args []string, out, errOut io.Writer) int {
	f := flag.NewFlagSet("init", flag.ContinueOnError)
	f.SetOutput(errOut)
	repoDir := f.String("repo", ".", "repository directory")
	language := f.String("language", "", "project language (auto-detected when omitted)")
	if err := f.Parse(args); err != nil {
		return flagCode(err)
	}
	if f.NArg() != 0 {
		return fail(errOut, 3, "init accepts no positional arguments")
	}
	if *language == "" {
		*language = detect(func(name string) bool { _, err := os.Stat(filepath.Join(*repoDir, name)); return err == nil })
	}
	if *language != "go" && *language != "typescript" && *language != "javascript" && *language != "python" && *language != "unknown" {
		return fail(errOut, 3, "unsupported language %q", *language)
	}
	c := config.Default(*language)
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fail(errOut, 3, "%v", err)
	}
	path := filepath.Join(*repoDir, config.Filename)
	fh, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fail(errOut, 3, "create configuration: %v", err)
	}
	_, writeErr := fh.Write(append(data, '\n'))
	closeErr := fh.Close()
	if writeErr != nil {
		return fail(errOut, 3, "%v", writeErr)
	}
	if closeErr != nil {
		return fail(errOut, 3, "%v", closeErr)
	}
	fmt.Fprintf(out, "Created %s (%s). Review commands and sandbox image, then commit this policy to your base branch.\nUse --config %s to explicitly try the local policy before committing it.\n", path, c.Language, path)
	return 0
}

func analyze(ctx context.Context, mode string, args []string, out, errOut io.Writer, version string) int {
	// --deadline counts from here unless the caller recorded an earlier start.
	if _, ok := ctx.Value(startKey{}).(time.Time); !ok {
		ctx = withStart(ctx, time.Now())
	}
	f := flag.NewFlagSet(mode, flag.ContinueOnError)
	f.SetOutput(errOut)
	repoPath := f.String("repo", ".", "repository directory")
	base := f.String("base", "main", "base branch or revision; its tip supplies the trusted policy")
	head := f.String("head", "HEAD", "candidate Git revision")
	exact := f.Bool("exact", false, "compare exact base instead of merge base")
	policyPath := f.String("config", "", "explicit trusted local configuration (default: policy at the tip of --base)")
	outDir := f.String("out", ".swiftproof", "report directory, relative to repository")
	format := f.String("format", "markdown,json", "comma-separated output formats: markdown,json")
	ci := f.Bool("ci", false, "return 2 when human review is required")
	checks := f.Bool("checks", mode == "review", "run configured checks in the Docker sandbox")
	useReviewer := f.Bool("reviewer", false, "use LLM investigation (default: enabled for review when a model is configured in policy or the environment); --reviewer=false disables provider calls")
	maxIterations := f.Int("max-iterations", 0, "override LLM iteration budget (1..100)")
	intent := f.String("intent", "", "PR intent or acceptance criteria")
	intentFile := f.String("intent-file", "", "UTF-8 file containing PR intent")
	allowNetwork := f.Bool("allow-network", false, "permit sandbox network only if trusted policy also enables it")
	noNetwork := f.Bool("no-network", false, "force sandbox networking off (use --reviewer=false to also disable the reviewer API)")
	reportURL := f.String("report-url", "", "https link to the full report, cited by the pr-comment format")
	baseTests := f.Bool("base-tests", false, "review: run the baseline versions of changed Go tests on candidate code")
	fuzzFlag := f.Bool("fuzz", true, "review: run the differential fuzzing that trusted policy configures; --fuzz=false records it as disabled")
	impactFlag := f.Bool("impact", true, "build the static impact index of changed Go functions (lint and review)")
	impactedTests := f.Bool("impacted-tests", false, "review: run unchanged Go tests that statically reach changed code on baseline and candidate")
	cacheDir := f.String("cache-dir", "", "review: opt-in baseline execution cache directory, outside the repository and the output directory")
	parallel := f.Int("parallel", 1, "review: number of initial checks run at a time (1..4)")
	allowPrepareNetwork := f.Bool("allow-prepare-network", false, "review: permit network for the trusted prepare container only, if policy prepare.network also enables it")
	deadline := f.Duration("deadline", 0, "review: overall time limit from 1m to 24h; 30s of it are kept for cleanup and the report")
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		args = append(append([]string{}, args[1:]...), args[0])
	}
	if err := f.Parse(args); err != nil {
		return flagCode(err)
	}
	formats, err := parseFormats(*format)
	if err != nil {
		return fail(errOut, 3, "%v", err)
	}
	opts, err := reportOptions(formats, *reportURL)
	if err != nil {
		return fail(errOut, 3, "%v", err)
	}
	explicit := visitedFlags(f)
	if err := validateExecutionFlags(mode, explicit, execFlags{checks: *checks, baseTests: *baseTests, impact: *impactFlag, impactedTests: *impactedTests, parallel: *parallel, cacheDir: *cacheDir, deadline: *deadline}); err != nil {
		return fail(errOut, 3, "%v", err)
	}
	mergeBase := !*exact
	if f.NArg() > 1 {
		return fail(errOut, 3, "expected at most one BASE..HEAD or BASE...HEAD range")
	}
	if f.NArg() == 1 {
		sep := ".."
		mergeBase = false
		if strings.Contains(f.Arg(0), "...") {
			sep = "..."
			mergeBase = true
		}
		parts := strings.Split(f.Arg(0), sep)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return fail(errOut, 3, "range must be BASE..HEAD or BASE...HEAD")
		}
		*base, *head = parts[0], parts[1]
	}
	if *intentFile != "" {
		if *intent != "" {
			return fail(errOut, 3, "use either --intent or --intent-file")
		}
		b, err := readLimited(*intentFile, 65536)
		if err != nil {
			return fail(errOut, 3, "intent: %v", err)
		}
		*intent = string(b)
	}
	if len(*intent) > 65536 {
		return fail(errOut, 3, "intent exceeds 64 KiB")
	}
	doc, err := parseIntent(*intent)
	if err != nil {
		return fail(errOut, 3, "intent: %v", err)
	}
	repo, err := gitrepo.Open(ctx, *repoPath)
	if err != nil {
		return fail(errOut, 3, "%v", err)
	}
	change, err := repo.Analyze(ctx, *base, *head, mergeBase)
	if err != nil {
		return fail(errOut, 3, "%v", err)
	}
	// The diff starts at the merge base, but the policy comes from the tip of
	// the base ref: the branch the change targets decides its current rules,
	// and a branch forked before the policy existed still gets it.
	cfg, policy, err := loadPolicy(ctx, repo, change.BaseRefCommit, *policyPath)
	if err != nil {
		return fail(errOut, 3, "%v", err)
	}
	if policy.Source == model.PolicyDefault {
		fmt.Fprintf(errOut, "No %s at %s (%s); using built-in %s defaults.\n", config.Filename, change.BaseRef, shortCommit(policy.Commit), cfg.Language)
	}
	if *maxIterations != 0 {
		cfg.Reviewer.MaxIterations = *maxIterations
	}
	if err := cfg.Validate(); err != nil {
		return fail(errOut, 3, "%v", err)
	}
	// Only trusted baseline policy (or explicit --config) can enable provider
	// traffic. A supplied boolean flag, including false, overrides auto-selection.
	reviewerExplicit := explicit["reviewer"]
	// Endpoint, model and credential come from the deployment: the same image
	// and the same trusted policy are pointed at the operator's provider
	// without a policy change. A misconfigured secret fails the run here
	// rather than downgrading it to an unauthenticated request.
	provider, err := cfg.ResolveReviewer(os.Getenv, os.ReadFile)
	if err != nil {
		return fail(errOut, 3, "%v", err)
	}
	if !reviewerExplicit {
		*useReviewer = mode == "review" && provider.Model != ""
	}
	if mode == "lint" && (*checks || *useReviewer) {
		return fail(errOut, 3, "lint does not execute checks or a reviewer; use review")
	}
	if *useReviewer && provider.Model == "" {
		return fail(errOut, 3, "reviewer.model must be configured in policy or %s before using --reviewer", config.ModelEnv)
	}
	reviewerOptions := reviewer.Options{Endpoint: provider.Endpoint, Model: provider.Model, APIKey: provider.APIKey, MaxIterations: cfg.Reviewer.MaxIterations, Timeout: time.Duration(cfg.Reviewer.TimeoutSeconds) * time.Second, MaxInputBytes: cfg.Reviewer.MaxInputBytes}
	if *useReviewer {
		if err := reviewer.Validate(reviewerOptions); err != nil {
			return fail(errOut, 3, "%v", err)
		}
		if len(provider.Sources) > 0 {
			fmt.Fprintf(errOut, "Reviewer configuration: %s.\n", strings.Join(provider.Sources, ", "))
		}
	}
	output := *outDir
	if !filepath.IsAbs(output) {
		output = filepath.Join(repo.Root, output)
	}
	output, err = filepath.Abs(output)
	if err != nil {
		return fail(errOut, 3, "%v", err)
	}
	if err := validateOutput(output); err != nil {
		return fail(errOut, 3, "%v", err)
	}
	// The cache directory is validated here, before dependency preparation and
	// before any container starts; nil when --cache-dir is unset (no Docker call).
	cache, err := openExecutionCache(repo.Root, output, *cacheDir, version, errOut)
	if err != nil {
		return fail(errOut, 3, "%v", err)
	}
	// Prepare, harness runs and the reviewer use work; static analysis,
	// snapshots, cleanup and report writing use the parent context.
	work, stopWork := workContext(ctx, *deadline)
	defer stopWork()
	signals, err := linter.Analyze(ctx, repo, change, cfg.SensitivePaths)
	if err != nil {
		return fail(errOut, 4, "linter: %v", err)
	}
	signals = linter.Merge(signals, prepareSignals(cfg.Prepare, change))
	impact, err := analyzeImpact(ctx, repo, change, *impactFlag)
	if err != nil {
		return fail(errOut, 4, "impact analysis: %v", err)
	}
	signals = linter.Merge(signals, impact.signals)
	r := model.Report{Version: 1, ToolVersion: version, GeneratedAt: time.Now().UTC(), Intent: doc.Text, IntentSHA256: doc.SHA256, IntentCriteria: doc.Criteria, Change: change, Policy: policy, Signals: signals, Impact: impact.report, Coverage: coverage.NotConfigured()}
	r.Unverified = append(r.Unverified, doc.Notes...)
	operationalFailure := false
	needExecution := mode == "review" && len(change.Files) > 0 && (*checks || *useReviewer)
	sc := stageContext{mode: mode, checks: *checks, reason: noExecutionReason(mode, change, *checks, *useReviewer)}
	image := cfg.Sandbox.Image
	var prep preparation
	if mode == "review" && cfg.Prepare != nil {
		if needExecution {
			executionStarted()
			prep = runPrepare(work, repo, cfg, change, filepath.Join(output, "artifacts"), cfg.Prepare.Network && *allowPrepareNetwork && !*noNetwork, version, errOut)
			if prep.ok {
				image = prep.image
			} else {
				// No fallback to the unprepared image: nothing executes, and the
				// run is an operational failure.
				needExecution, operationalFailure, sc.reason = false, true, reasonPrepareFailed
			}
		} else {
			prep = preparation{record: prepareNotRun(cfg, change, sc.reason)}
		}
		r.Prepare = prep.record
		r.Unverified = append(r.Unverified, prep.unverified...)
	}
	if needExecution {
		sc.executed = true
		temp, err := os.MkdirTemp("", "swiftproof-")
		if err != nil {
			return fail(errOut, 4, "%v", err)
		}
		defer os.RemoveAll(temp)
		candidateDir, baseDir := filepath.Join(temp, "candidate"), filepath.Join(temp, "base")
		if err := repo.Snapshot(ctx, change.HeadCommit, candidateDir); err != nil {
			return fail(errOut, 4, "candidate snapshot: %v", err)
		}
		if err := repo.Snapshot(ctx, change.BaseCommit, baseDir); err != nil {
			return fail(errOut, 4, "base snapshot: %v", err)
		}
		diffJSON, _ := json.Marshal(change)
		executionStarted()
		h, err := harness.New(harness.Options{
			CandidateDir: candidateDir, BaseDir: baseDir, ArtifactDir: filepath.Join(output, "artifacts"),
			Commands: cfg.Commands, Image: image, Network: cfg.Sandbox.Network && *allowNetwork && !*noNetwork,
			Timeout: time.Duration(cfg.Sandbox.TimeoutSeconds) * time.Second, MaxRuntime: time.Duration(cfg.Sandbox.MaxRuntimeSeconds) * time.Second,
			MaxGeneratedTests: cfg.Reviewer.MaxGeneratedTests, MaxOutputBytes: cfg.Sandbox.MaxOutputBytes,
			MemoryMB: cfg.Sandbox.MemoryMB, CPUs: cfg.Sandbox.CPUs, Diff: string(diffJSON),
			IntentCriteria: r.IntentCriteria, Symbols: impact.lookup, Cache: cache, Parallel: *parallel,
			ReviewerReserve: reviewerReserve(cfg, *useReviewer),
		})
		if err != nil {
			return fail(errOut, 4, "harness: %v", err)
		}
		defer h.Close()
		// Stage order: initial checks, coverage, baseline versions of changed
		// tests, impacted tests, fuzzing, mutation, then the reviewer. The
		// cheapest and strongest deterministic evidence comes first.
		if *checks {
			if kinds := initialChecks(cfg.Commands); len(kinds) > 0 {
				fmt.Fprintf(errOut, "Running %s in isolated Docker sandboxes...\n", strings.Join(kinds, ", "))
				for _, c := range h.RunChecks(work, kinds) {
					if c.Status == "ERROR" {
						operationalFailure = true
					}
				}
			}
			// Coverage runs after the initial checks and in addition to the
			// configured test command, so the shared runtime budget starves the
			// measurement rather than the checks a repository already relies on.
			covered := coverage.Result{}
			if _, configured := cfg.Commands[coverage.CommandKey]; configured {
				fmt.Fprintf(errOut, "Running %s in isolated Docker sandbox...\n", coverage.CommandKey)
				check, profile, sha, reason := h.RunCoverage(work)
				if check.Status == "ERROR" {
					operationalFailure = true
				}
				result := coverage.NotMeasured(reason)
				if reason == "" {
					result = measure(profile, candidateDir, check, sha, change)
				}
				r.Coverage = result.Report()
				// Coverage may add signals and add sentences; it never deletes a
				// signal, lowers a severity or supports a dismissal.
				r.Signals = linter.Merge(coverage.Requalify(r.Signals, result), result.Signals())
				if result.Status() != coverage.StatusMeasured {
					r.Unverified = append(r.Unverified, "Changed-line execution was not measured: "+r.Coverage.Reason)
				}
				if reason == "" && check.Status == "PASS" {
					covered = result
				}
			}
			if *baseTests && runBaseTests(work, repo, change, h, &r, errOut) {
				operationalFailure = true
			}
			if *impactedTests && runImpactedTests(work, h, &r, impact, errOut) {
				operationalFailure = true
			}
			runFuzz(work, h, cfg, change, baseDir, candidateDir, &r, *fuzzFlag, errOut)
			if cfg.Mutation != nil && runMutation(work, h, cfg, change, covered, &r, errOut) {
				operationalFailure = true
			}
		}
		r.Checks, r.Evidence, r.Audit = h.Checks(), h.Evidence(), h.Audit()
		auditBefore := len(r.Audit)
		if *useReviewer {
			fmt.Fprintln(errOut, "Investigating with the configured reviewer API...")
			err := reviewer.Run(work, reviewerOptions, &r, h)
			if err != nil {
				r.Unverified = append(r.Unverified, "Reviewer incomplete: "+err.Error())
			}
		}
		r.Checks, r.Evidence, r.Artifacts = h.Checks(), h.Evidence(), h.Artifacts()
		r.Audit = append(r.Audit, h.Audit()[auditBefore:]...)
		sort.SliceStable(r.Audit, func(i, j int) bool { return r.Audit[i].Time.Before(r.Audit[j].Time) })
		r.Execution = executionSummary(h, work)
		for _, c := range r.Checks {
			if c.Status == "ERROR" {
				operationalFailure = true
			}
		}
	} else if mode == "review" && len(change.Files) > 0 && !(*checks || *useReviewer) {
		r.Unverified = append(r.Unverified, "Automated execution was explicitly disabled; only static change analysis was performed.")
	}
	if deadlineReached(ctx, work) {
		r.Unverified = append(r.Unverified, deadlineNote)
	}
	// A requested or configured stage that did not run still records its
	// section, with the reason (present means requested).
	recordFuzzSkipped(cfg, sc, *fuzzFlag, &r)
	recordBaseTestsSkipped(sc, *baseTests, &r)
	recordImpactedTestsSkipped(sc, *impactedTests, &r)
	recordMutationSkipped(cfg, sc, &r)
	r.Artifacts = append(prep.artifacts, r.Artifacts...)
	r.Audit = append(prep.audit, r.Audit...)
	for i := range r.Artifacts {
		if relative, err := filepath.Rel(output, r.Artifacts[i].Path); err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			r.Artifacts[i].Path = filepath.ToSlash(relative)
		}
	}
	report.Finalize(&r, *ci)
	if operationalFailure {
		r.ExitCode = 4
	}
	if err := report.Write(output, &r, formats, opts...); err != nil {
		return fail(errOut, 4, "write report: %v", err)
	}
	fmt.Fprintf(out, "%d files, +%d/-%d lines; %d risk signals; %d reproduced issues.\nFocused review: %d / %d changed lines (a prioritization aid, not a correctness guarantee).\n", len(change.Files), change.Additions, change.Deletions, len(r.Signals), len(r.ReproducedIssues), r.ReviewSurface.FocusedLines, r.ReviewSurface.ChangedLines)
	if r.Coverage.Status == coverage.StatusMeasured {
		fmt.Fprintf(out, "Changed-line execution: %d executed, %d not executed, %d outside any instrumented block, %d not measured, of %d added Go lines.\n", r.Coverage.ExecutedLines, r.Coverage.NotExecutedLines, r.Coverage.NoBlockLines, r.Coverage.NotMeasuredLines, r.Coverage.AddedLines)
	} else {
		fmt.Fprintln(out, "Changed-line execution: not measured.")
	}
	for _, line := range stdoutLines(&r) {
		fmt.Fprintln(out, line)
	}
	fmt.Fprintf(out, "Reports: %s\n", output)
	return r.ExitCode
}

// measure resolves the recorded profile against the diff. Every failure short of
// a complete, mapped measurement returns "not measured": there is no path from
// missing data to a not-executed claim.
func measure(profile []byte, candidateDir string, check model.Check, sha string, change model.Change) coverage.Result {
	module, workspace, err := coverage.Modules(candidateDir)
	if err != nil {
		return coverage.NotMeasured(err.Error())
	}
	parsed, err := coverage.ParseGoProfile(profile)
	if err != nil {
		return coverage.NotMeasured(err.Error())
	}
	return coverage.Analyze(parsed, coverage.Run{CheckID: check.ID, Status: check.Status, Command: check.Command, SHA256: sha, Module: module, Workspace: workspace}, change)
}

// loadPolicy reads the trusted policy from commit, the resolved base ref, unless
// the caller explicitly selects a local file. It never reads the candidate.
func loadPolicy(ctx context.Context, repo *gitrepo.Repository, commit, explicit string) (config.Config, model.Policy, error) {
	if explicit != "" {
		policy := model.Policy{Source: model.PolicyExplicit, Path: explicit}
		b, err := readLimited(explicit, 1<<20)
		if err != nil {
			return config.Config{}, policy, err
		}
		cfg, err := config.Decode(b)
		return cfg, policy, err
	}
	policy := model.Policy{Source: model.PolicyBaseRef, Commit: commit, Path: config.Filename}
	b, err := repo.ReadFile(ctx, commit, config.Filename)
	if err == nil {
		cfg, err := config.Decode(b)
		return cfg, policy, err
	}
	if !errors.Is(err, gitrepo.ErrNotFound) {
		return config.Config{}, policy, fmt.Errorf("load base policy: %w", err)
	}
	language := detect(func(name string) bool { _, err := repo.ReadFile(ctx, commit, name); return err == nil })
	return config.Default(language), model.Policy{Source: model.PolicyDefault, Commit: commit}, nil
}

func shortCommit(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

func detect(exists func(string) bool) string {
	for _, item := range []struct{ file, language string }{{"go.mod", "go"}, {"go.work", "go"}, {"tsconfig.json", "typescript"}, {"package.json", "javascript"}, {"pyproject.toml", "python"}, {"setup.py", "python"}} {
		if exists(item.file) {
			return item.language
		}
	}
	return "unknown"
}

func render(args []string, out, errOut io.Writer) int {
	f := flag.NewFlagSet("report", flag.ContinueOnError)
	f.SetOutput(errOut)
	input := f.String("input", ".swiftproof/confidence-report.json", "saved JSON report")
	dir := f.String("out", ".swiftproof", "output directory")
	format := f.String("format", "markdown,json", "comma-separated output formats: markdown,json")
	reportURL := f.String("report-url", "", "https link to the full report, cited by the pr-comment format")
	if err := f.Parse(args); err != nil {
		return flagCode(err)
	}
	if f.NArg() != 0 {
		return fail(errOut, 3, "report accepts no positional arguments")
	}
	formats, err := parseFormats(*format)
	if err != nil {
		return fail(errOut, 3, "%v", err)
	}
	opts, err := reportOptions(formats, *reportURL)
	if err != nil {
		return fail(errOut, 3, "%v", err)
	}
	b, err := readLimited(*input, 64<<20)
	if err != nil {
		return fail(errOut, 3, "%v", err)
	}
	var r model.Report
	if err := json.Unmarshal(b, &r); err != nil {
		return fail(errOut, 3, "%v", err)
	}
	if r.Version != 1 {
		return fail(errOut, 3, "unsupported report version %d", r.Version)
	}
	if r.ExitCode < 0 || r.ExitCode > 4 {
		return fail(errOut, 3, "invalid report exit code %d", r.ExitCode)
	}
	previousExit := r.ExitCode
	report.Finalize(&r, previousExit == 2)
	if previousExit == 4 {
		r.ExitCode = 4
	}
	if err := validateOutput(*dir); err != nil {
		return fail(errOut, 3, "%v", err)
	}
	if err := report.Write(*dir, &r, formats, opts...); err != nil {
		return fail(errOut, 4, "%v", err)
	}
	fmt.Fprintf(out, "Reports: %s\n", *dir)
	return 0
}

func parseFormats(s string) ([]string, error) {
	var formats []string
	seen := map[string]bool{}
	for _, value := range strings.Split(s, ",") {
		value = strings.TrimSpace(value)
		if !report.ValidFormat(value) {
			return nil, fmt.Errorf("unknown report format %q", value)
		}
		if !seen[value] {
			formats = append(formats, value)
			seen[value] = true
		}
	}
	return formats, nil
}
func readLimited(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%s exceeds %d bytes", path, limit)
	}
	return b, nil
}
func validateOutput(dir string) error {
	absolute, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	for p := absolute; ; p = filepath.Dir(p) {
		info, err := os.Lstat(p)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err == nil && (info.Mode()&os.ModeSymlink != 0 || !info.IsDir()) && !fsutil.IsSystemAlias(p) {
			return fmt.Errorf("output path must contain only directories, not links: %s", p)
		}
		if filepath.Dir(p) == p {
			break
		}
	}
	return nil
}
func fail(w io.Writer, code int, format string, args ...any) int {
	fmt.Fprintf(w, "swiftproof: "+format+"\n", args...)
	return code
}
func flagCode(err error) int {
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	return 3
}
