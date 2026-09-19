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

	"github.com/gvinsot/SwiftProof/internal/config"
	"github.com/gvinsot/SwiftProof/internal/fsutil"
	"github.com/gvinsot/SwiftProof/internal/gitrepo"
	"github.com/gvinsot/SwiftProof/internal/harness"
	"github.com/gvinsot/SwiftProof/internal/linter"
	"github.com/gvinsot/SwiftProof/internal/model"
	"github.com/gvinsot/SwiftProof/internal/report"
	"github.com/gvinsot/SwiftProof/internal/reviewer"
)

const usage = `SwiftProof — evidence for focused review of AI-assisted changes

Usage:
  swiftproof init [--repo PATH] [--language go|typescript|python]
  swiftproof lint [--base main] [--head HEAD] [--ci]
  swiftproof review [--base main] [--reviewer] [--ci]
  swiftproof review [flags] BASE..HEAD
  swiftproof report [--input .swiftproof/confidence-report.json] [--out DIR]
  swiftproof version

Analysis compares the merge base by default; BASE..HEAD compares exact commits.
Only committed files are reviewed. Output defaults to .swiftproof/.
Review runs configured checks in Docker. Lint never executes repository code.
The optional reviewer sends bounded, redacted source context to its configured API.
Use 'swiftproof <command> --help' for options.
`

func Run(ctx context.Context, args []string, stdout, stderr io.Writer, version string) int {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		fmt.Fprint(stdout, usage)
		return 0
	}
	switch args[0] {
	case "version", "--version":
		fmt.Fprintf(stdout, "swiftproof %s\n", version)
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
	f := flag.NewFlagSet(mode, flag.ContinueOnError)
	f.SetOutput(errOut)
	repoPath := f.String("repo", ".", "repository directory")
	base := f.String("base", "main", "base Git revision")
	head := f.String("head", "HEAD", "candidate Git revision")
	exact := f.Bool("exact", false, "compare exact base instead of merge base")
	policyPath := f.String("config", "", "explicit trusted local configuration (default: policy from base commit)")
	outDir := f.String("out", ".swiftproof", "report directory, relative to repository")
	format := f.String("format", "markdown,json", "comma-separated output formats: markdown,json")
	ci := f.Bool("ci", false, "return 2 when human review is required")
	checks := f.Bool("checks", mode == "review", "run configured checks in the Docker sandbox")
	useReviewer := f.Bool("reviewer", false, "enable remote LLM investigation; sends redacted source context")
	maxIterations := f.Int("max-iterations", 0, "override LLM iteration budget (1..100)")
	intent := f.String("intent", "", "PR intent or acceptance criteria")
	intentFile := f.String("intent-file", "", "UTF-8 file containing PR intent")
	allowNetwork := f.Bool("allow-network", false, "permit sandbox network only if trusted policy also enables it")
	noNetwork := f.Bool("no-network", false, "force sandbox networking off (does not disable the opt-in reviewer API)")
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
	repo, err := gitrepo.Open(ctx, *repoPath)
	if err != nil {
		return fail(errOut, 3, "%v", err)
	}
	change, err := repo.Analyze(ctx, *base, *head, mergeBase)
	if err != nil {
		return fail(errOut, 3, "%v", err)
	}
	cfg, err := loadPolicy(ctx, repo, change.BaseCommit, *policyPath)
	if err != nil {
		return fail(errOut, 3, "%v", err)
	}
	if *maxIterations != 0 {
		cfg.Reviewer.MaxIterations = *maxIterations
	}
	if err := cfg.Validate(); err != nil {
		return fail(errOut, 3, "%v", err)
	}
	if *useReviewer && cfg.Reviewer.Model == "" {
		return fail(errOut, 3, "reviewer.model must be configured before using --reviewer")
	}
	reviewerOptions := reviewer.Options{Endpoint: cfg.Reviewer.Endpoint, Model: cfg.Reviewer.Model, APIKey: os.Getenv(cfg.Reviewer.APIKeyEnv), MaxIterations: cfg.Reviewer.MaxIterations, Timeout: time.Duration(cfg.Reviewer.TimeoutSeconds) * time.Second, MaxInputBytes: cfg.Reviewer.MaxInputBytes}
	if *useReviewer {
		if err := reviewer.Validate(reviewerOptions); err != nil {
			return fail(errOut, 3, "%v", err)
		}
	}
	if mode == "lint" && (*checks || *useReviewer) {
		return fail(errOut, 3, "lint does not execute checks or a reviewer; use review")
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
	signals, err := linter.Analyze(ctx, repo, change, cfg.SensitivePaths)
	if err != nil {
		return fail(errOut, 4, "linter: %v", err)
	}
	r := model.Report{Version: 1, ToolVersion: version, GeneratedAt: time.Now().UTC(), Intent: *intent, Change: change, Signals: signals}
	operationalFailure := false
	if mode == "review" && len(change.Files) > 0 && (*checks || *useReviewer) {
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
		h, err := harness.New(harness.Options{
			CandidateDir: candidateDir, BaseDir: baseDir, ArtifactDir: filepath.Join(output, "artifacts"),
			Commands: cfg.Commands, Image: cfg.Sandbox.Image, Network: cfg.Sandbox.Network && *allowNetwork && !*noNetwork,
			Timeout: time.Duration(cfg.Sandbox.TimeoutSeconds) * time.Second, MaxRuntime: time.Duration(cfg.Sandbox.MaxRuntimeSeconds) * time.Second,
			MaxGeneratedTests: cfg.Reviewer.MaxGeneratedTests, MaxOutputBytes: cfg.Sandbox.MaxOutputBytes,
			MemoryMB: cfg.Sandbox.MemoryMB, CPUs: cfg.Sandbox.CPUs, Diff: string(diffJSON),
		})
		if err != nil {
			return fail(errOut, 4, "harness: %v", err)
		}
		defer h.Close()
		if *checks {
			for _, kind := range []string{"test", "typecheck", "build"} {
				if _, ok := cfg.Commands[kind]; !ok {
					continue
				}
				fmt.Fprintf(errOut, "Running %s in isolated Docker sandbox...\n", kind)
				check := h.Run(ctx, kind)
				if check.Status == "ERROR" {
					operationalFailure = true
				}
			}
		}
		r.Checks, r.Evidence, r.Audit = h.Checks(), h.Evidence(), h.Audit()
		auditBefore := len(r.Audit)
		if *useReviewer {
			fmt.Fprintln(errOut, "Investigating with the configured reviewer API...")
			err := reviewer.Run(ctx, reviewerOptions, &r, h)
			if err != nil {
				r.Unverified = append(r.Unverified, "Reviewer incomplete: "+err.Error())
			}
		}
		r.Checks, r.Evidence, r.Artifacts = h.Checks(), h.Evidence(), h.Artifacts()
		r.Audit = append(r.Audit, h.Audit()[auditBefore:]...)
		sort.SliceStable(r.Audit, func(i, j int) bool { return r.Audit[i].Time.Before(r.Audit[j].Time) })
		for _, c := range r.Checks {
			if c.Status == "ERROR" {
				operationalFailure = true
			}
		}
	} else if mode == "review" && len(change.Files) > 0 {
		r.Unverified = append(r.Unverified, "Automated execution was explicitly disabled; only static change analysis was performed.")
	}
	for i := range r.Artifacts {
		if relative, err := filepath.Rel(output, r.Artifacts[i].Path); err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			r.Artifacts[i].Path = filepath.ToSlash(relative)
		}
	}
	report.Finalize(&r, *ci)
	if operationalFailure {
		r.ExitCode = 4
	}
	if err := report.Write(output, &r, formats); err != nil {
		return fail(errOut, 4, "write report: %v", err)
	}
	fmt.Fprintf(out, "%d files, +%d/-%d lines; %d risk signals; %d reproduced issues.\nFocused review: %d / %d changed lines (a prioritization aid, not a correctness guarantee).\nReports: %s\n", len(change.Files), change.Additions, change.Deletions, len(r.Signals), len(r.ReproducedIssues), r.ReviewSurface.FocusedLines, r.ReviewSurface.ChangedLines, output)
	return r.ExitCode
}

func loadPolicy(ctx context.Context, repo *gitrepo.Repository, base, explicit string) (config.Config, error) {
	if explicit != "" {
		b, err := readLimited(explicit, 1<<20)
		if err != nil {
			return config.Config{}, err
		}
		return config.Decode(b)
	}
	b, err := repo.ReadFile(ctx, base, config.Filename)
	if err == nil {
		return config.Decode(b)
	}
	if !errors.Is(err, gitrepo.ErrNotFound) {
		return config.Config{}, fmt.Errorf("load base policy: %w", err)
	}
	language := detect(func(name string) bool { _, err := repo.ReadFile(ctx, base, name); return err == nil })
	return config.Default(language), nil
}

func detect(exists func(string) bool) string {
	for _, item := range []struct{ file, language string }{{"go.mod", "go"}, {"tsconfig.json", "typescript"}, {"package.json", "javascript"}, {"pyproject.toml", "python"}, {"setup.py", "python"}} {
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
	format := f.String("format", "markdown,json", "output formats")
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
	if err := report.Write(*dir, &r, formats); err != nil {
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
		if value != "markdown" && value != "json" {
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
