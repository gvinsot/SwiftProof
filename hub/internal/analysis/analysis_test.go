package analysis

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/gvinsot/SwiftProof/hub/internal/config"
	"github.com/gvinsot/SwiftProof/hub/internal/events"
	"github.com/gvinsot/SwiftProof/hub/internal/report"
	"github.com/gvinsot/SwiftProof/hub/internal/store"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func testRunner(t *testing.T, binary string) (*Runner, *store.Store) {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	cfg := config.Config{
		BaseURL: "https://hub.example", Mode: config.ModeLint, Binary: binary,
		Workers: 1, QueueSize: 4, AnalysisTimeout: time.Minute, CloneDepth: 5,
	}
	return New(cfg, st, nil, events.New(), discardLogger()), st
}

/* --------------------------------------------------------------- git -- */

// repoWithCommits builds a throwaway repository and returns its commits in
// chronological order.
func repoWithCommits(t *testing.T, n int) (*gitRunner, []string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the git fixture uses a POSIX shell environment")
	}
	dir := t.TempDir()
	g := &gitRunner{dir: dir, env: append(gitEnv(dir, "", ""),
		"GIT_AUTHOR_NAME=SwiftProof", "GIT_AUTHOR_EMAIL=test@example.com",
		"GIT_COMMITTER_NAME=SwiftProof", "GIT_COMMITTER_EMAIL=test@example.com",
	)}
	ctx := context.Background()
	if _, err := g.run(ctx, "init", "--quiet", "--initial-branch=main"); err != nil {
		t.Skipf("git is not usable here: %v", err)
	}
	commits := make([]string, 0, n)
	for i := 0; i < n; i++ {
		name := filepath.Join(dir, "file.txt")
		if err := os.WriteFile(name, []byte(strings.Repeat("line\n", i+1)), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		if _, err := g.run(ctx, "add", "file.txt"); err != nil {
			t.Fatalf("git add: %v", err)
		}
		if _, err := g.run(ctx, "commit", "--quiet", "-m", "change"); err != nil {
			t.Fatalf("git commit: %v", err)
		}
		sha, err := g.run(ctx, "rev-parse", "HEAD")
		if err != nil {
			t.Fatalf("git rev-parse: %v", err)
		}
		commits = append(commits, sha)
	}
	return g, commits
}

func TestResolveBaseUsesTheCommitTheBranchPointedAt(t *testing.T) {
	g, commits := repoWithCommits(t, 3)
	head := commits[2]
	if got := g.resolveBase(context.Background(), commits[0], head, 5); got != commits[0] {
		t.Errorf("resolveBase = %s, want the pushed-from commit %s", got, commits[0])
	}
}

func TestResolveBaseFallsBackToTheFirstParent(t *testing.T) {
	g, commits := repoWithCommits(t, 2)
	head := commits[1]
	// A zero "before" is what a forge sends for a newly created branch.
	zero := strings.Repeat("0", 40)
	if got := g.resolveBase(context.Background(), zero, head, 5); got != commits[0] {
		t.Errorf("resolveBase = %s, want the parent %s", got, commits[0])
	}
	if got := g.resolveBase(context.Background(), "", head, 5); got != commits[0] {
		t.Errorf("resolveBase with no before = %s, want the parent", got)
	}
}

func TestResolveBaseOnAnInitialCommitComparesAgainstItself(t *testing.T) {
	g, commits := repoWithCommits(t, 1)
	// No parent exists: an empty range is honest, a wrong base is not.
	if got := g.resolveBase(context.Background(), "", commits[0], 5); got != commits[0] {
		t.Errorf("resolveBase = %s, want the commit itself", got)
	}
}

func TestHasRejectsAnUnknownCommit(t *testing.T) {
	g, commits := repoWithCommits(t, 1)
	ctx := context.Background()
	if !g.has(ctx, commits[0]) {
		t.Error("a local commit must be found")
	}
	if g.has(ctx, strings.Repeat("a", 40)) {
		t.Error("an absent commit must not be reported as present")
	}
	if g.has(ctx, "") {
		t.Error("an empty revision must not be reported as present")
	}
}

func TestGitEnvScopesTheCredentialToTheRemote(t *testing.T) {
	env := gitEnv("/work", "https://github.com/acme/shop.git", "Basic dXNlcjp0b2tlbg==")
	joined := strings.Join(env, "\n")
	if !strings.Contains(joined, "GIT_CONFIG_KEY_0=http.https://github.com/acme/shop.git.extraheader") {
		t.Errorf("the credential must be scoped to the remote URL:\n%s", joined)
	}
	if !strings.Contains(joined, "GIT_CONFIG_NOSYSTEM=1") || !strings.Contains(joined, "GIT_TERMINAL_PROMPT=0") {
		t.Errorf("git must not read host configuration or prompt:\n%s", joined)
	}
	// Without a credential no config override is injected at all.
	bare := strings.Join(gitEnv("/work", "https://host/x.git", ""), "\n")
	if strings.Contains(bare, "GIT_CONFIG_COUNT") {
		t.Errorf("no credential means no injected config:\n%s", bare)
	}
}

func TestPrepareRefusesANonHTTPRemote(t *testing.T) {
	g := &gitRunner{dir: t.TempDir(), env: gitEnv(t.TempDir(), "", "")}
	ctx := context.Background()
	for _, remote := range []string{"", "git@github.com:acme/shop.git", "file:///etc", "ssh://host/repo"} {
		if err := g.prepare(ctx, remote); err == nil {
			t.Errorf("prepare(%q) must be refused", remote)
		}
	}
}

/* --------------------------------------------------------------- CLI -- */

// fakeCLI installs a stand-in for the SwiftProof binary.
func fakeCLI(t *testing.T, script string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the fake CLI is a POSIX shell script")
	}
	path := filepath.Join(t.TempDir(), "swiftproof")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+script), 0o700); err != nil {
		t.Fatalf("write fake CLI: %v", err)
	}
	return path
}

const fakeReport = `{"version":1,"tool_version":"v9.9.9","generated_at":"2026-09-25T10:00:00Z",
"change":{"base_ref":"main","head_ref":"HEAD","base_commit":"aaa","head_commit":"bbb","files":[],"additions":0,"deletions":0},
"linter":[{"id":"s1","kind":"k","path":"a.go","line":1,"severity":"high","summary":"s","evidence":"e"}],
"checks":[],"hypotheses":[],"evidence":[],"reproduced_issues":[],"unverified":["nothing ran"],
"review_targets":[],"review_surface":{"changed_lines":0,"focused_lines":0,"note":""},
"coverage":{"status":"not_configured","added_lines":0,"executed_lines":0,"not_executed_lines":0,"no_block_lines":0,"not_measured_lines":0,"removed_lines":0,"files":[],"note":""},
"artifacts":[],"audit":[],"exit_code":2}`

func TestRunCLIPassesTheExactRangeAndReadsTheReport(t *testing.T) {
	binary := fakeCLI(t, `
echo "$@" > args.txt
mkdir -p .swiftproof
cat > .swiftproof/confidence-report.json <<'JSON'
`+fakeReport+`
JSON
exit 2
`)
	r, _ := testRunner(t, binary)
	work := t.TempDir()
	output, code, err := r.runCLI(context.Background(), work, "base-sha", "head-sha")
	if code != 2 {
		t.Fatalf("exit code = %d (%v), want 2: %s", code, err, output)
	}
	args, readErr := os.ReadFile(filepath.Join(work, "args.txt"))
	if readErr != nil {
		t.Fatalf("the CLI must run inside the prepared checkout: %v", readErr)
	}
	for _, want := range []string{"lint", "--base base-sha", "--head head-sha", "--exact", "--ci", "--format json,markdown"} {
		if !strings.Contains(string(args), want) {
			t.Errorf("arguments %q miss %q", args, want)
		}
	}
	data, err := readBounded(filepath.Join(work, reportPath), maxReportBytes)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	parsed, err := report.Decode(data)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if parsed.Summarize().Verdict != report.VerdictReview {
		t.Errorf("verdict = %q, want review for exit code 2", parsed.Summarize().Verdict)
	}
}

func TestPolicyIsGeneratedByTheInstalledCLI(t *testing.T) {
	binary := fakeCLI(t, `
dir=""
lang=""
while [ $# -gt 0 ]; do
  case "$1" in
    --repo) dir="$2"; shift 2;;
    --language) lang="$2"; shift 2;;
    *) shift;;
  esac
done
printf '{"version":1,"language":"%s","commands":{}}' "$lang" > "$dir/.swiftproof.json"
`)
	r, _ := testRunner(t, binary)
	policy, err := r.Policy(context.Background(), "go")
	if err != nil {
		t.Fatalf("Policy: %v", err)
	}
	if !strings.Contains(string(policy), `"language": "go"`) {
		t.Errorf("the generated policy must carry the language, got %s", policy)
	}
	if !strings.HasSuffix(string(policy), "}\n") {
		t.Errorf("the committed file must be indented and newline terminated, got %q", policy)
	}
	if _, err := r.Policy(context.Background(), "cobol"); err == nil {
		t.Error("an unsupported language must be refused before running anything")
	}
}

func TestPolicyReportsAFailingCLI(t *testing.T) {
	r, _ := testRunner(t, fakeCLI(t, "echo boom >&2; exit 3"))
	if _, err := r.Policy(context.Background(), "go"); err == nil {
		t.Fatal("a failing CLI must be reported")
	}
}

func TestSupportedLanguage(t *testing.T) {
	for _, ok := range Languages {
		if !SupportedLanguage(ok) {
			t.Errorf("SupportedLanguage(%q) must be true", ok)
		}
	}
	if SupportedLanguage("rust") || SupportedLanguage("") {
		t.Error("an unknown language must be refused")
	}
}

/* ------------------------------------------------------------- queue -- */

func TestEnqueueValidatesRejectsDuplicatesAndReportsSaturation(t *testing.T) {
	r, st := testRunner(t, "/bin/true")
	userKey, repoKey := store.Key("github", "1"), store.Key("github", "10")
	if err := st.PutRepo(userKey, &store.Repo{Key: repoKey, FullName: "acme/shop"}); err != nil {
		t.Fatalf("PutRepo: %v", err)
	}
	job := Job{UserKey: userKey, RepoKey: repoKey, Commit: "abc1234", Trigger: TriggerPush}

	if err := r.Enqueue(Job{UserKey: userKey, RepoKey: repoKey, Commit: "not-a-sha!"}); err == nil {
		t.Error("an invalid commit must be refused")
	}
	if err := r.Enqueue(job); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	if r.Pending() != 1 {
		t.Fatalf("queue depth = %d, want 1", r.Pending())
	}
	// A redelivery of the same push must not queue the work twice.
	if err := r.Enqueue(job); err != nil {
		t.Fatalf("a duplicate must be accepted silently, got %v", err)
	}
	if r.Pending() != 1 {
		t.Errorf("queue depth = %d after a duplicate, want 1", r.Pending())
	}

	for i := 0; i < 3; i++ {
		other := job
		other.Commit = "abc123" + string(rune('a'+i))
		if err := r.Enqueue(other); err != nil {
			t.Fatalf("Enqueue %d: %v", i, err)
		}
	}
	saturated := job
	saturated.Commit = "ffffff0"
	if err := r.Enqueue(saturated); !errors.Is(err, ErrBusy) {
		t.Errorf("a full queue must report ErrBusy so the forge retries, got %v", err)
	}

	// The latest run is published on the repository as soon as it is queued.
	stored, err := st.Repo(userKey, repoKey)
	if err != nil || stored.Latest == nil || stored.Latest.Status != store.StatusQueued {
		t.Fatalf("latest run = %+v, %v", stored.Latest, err)
	}
}

func TestStatusDescriptionStatesWhatWasRecorded(t *testing.T) {
	blocked := store.Run{Status: store.StatusDone}
	blocked.Summary = report.Summary{Verdict: report.VerdictBlocked, Reproduced: 1}
	blocked.Summary.Counts.Add(report.SeverityCritical)
	if got := statusDescription(blocked); !strings.Contains(got, "reproduced") {
		t.Errorf("description = %q", got)
	}

	review := store.Run{Status: store.StatusDone}
	review.Summary = report.Summary{Verdict: report.VerdictReview, ChangedLines: 10, FocusedLines: 3}
	if got := statusDescription(review); !strings.Contains(got, "Human review required") {
		t.Errorf("description = %q", got)
	}

	clear := store.Run{Status: store.StatusDone}
	clear.Summary = report.Summary{Verdict: report.VerdictClear}
	got := statusDescription(clear)
	if strings.Contains(strings.ToLower(got), "approved") || strings.Contains(strings.ToLower(got), "safe") {
		t.Errorf("a clear run must never be worded as an approval: %q", got)
	}

	failed := store.Run{Status: store.StatusFailed}
	if got := statusDescription(failed); !strings.Contains(got, "could not complete") {
		t.Errorf("description = %q", got)
	}
}

func TestFirstLineAndTail(t *testing.T) {
	if got := firstLine("fix refund\n\nlong body"); got != "fix refund" {
		t.Errorf("firstLine = %q", got)
	}
	if got := firstLine(strings.Repeat("x", 300)); len([]rune(got)) != 200 {
		t.Errorf("firstLine length = %d runes, want 200", len([]rune(got)))
	}
	long := strings.Repeat("y", maxOutputBytes+100)
	if got := tail(long); len(got) > maxOutputBytes+4 {
		t.Errorf("tail length = %d, want a bounded output", len(got))
	}
}
