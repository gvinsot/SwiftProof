package gitrepo

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gvinsot/SwiftProof/app/internal/model"
)

func gitTest(t *testing.T, dir string, input string, args ...string) string {
	t.Helper()
	c := exec.Command("git", append([]string{"-C", dir}, args...)...)
	c.Stdin = strings.NewReader(input)
	c.Env = append(os.Environ(), "GIT_AUTHOR_NAME=SwiftProof Test", "GIT_AUTHOR_EMAIL=test@example.invalid", "GIT_COMMITTER_NAME=SwiftProof Test", "GIT_COMMITTER_EMAIL=test@example.invalid", "GIT_CONFIG_NOSYSTEM=1")
	out, err := c.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}
func newTestRepo(t *testing.T) (string, *Repository) {
	t.Helper()
	dir := t.TempDir()
	gitTest(t, dir, "", "init", "-b", "main")
	gitTest(t, dir, "", "config", "core.autocrlf", "false")
	r, err := Open(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	return dir, r
}
func writeTest(t *testing.T, dir, p, s string) {
	t.Helper()
	target := filepath.Join(dir, p)
	if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte(s), 0600); err != nil {
		t.Fatal(err)
	}
}
func commitTest(t *testing.T, dir string) string {
	t.Helper()
	gitTest(t, dir, "", "add", "-A")
	return commitIndex(t, dir)
}
func commitIndex(t *testing.T, dir string) string {
	t.Helper()
	gitTest(t, dir, "", "commit", "--no-gpg-sign", "-m", "test")
	return gitTest(t, dir, "", "rev-parse", "HEAD")
}

func TestAnalyzeImmutableRenameBinaryDeletionAndUnusualPath(t *testing.T) {
	dir, r := newTestRepo(t)
	ctx := context.Background()
	writeTest(t, dir, "main.go", "package app\nfunc Version() string { return \"old\" }\n")
	writeTest(t, dir, "old name.txt", "unchanged rename contents\n")
	writeTest(t, dir, "deleted.txt", "deleted\n")
	writeTest(t, dir, "image.bin", "\x00old")
	base := commitTest(t, dir)
	if err := os.Rename(filepath.Join(dir, "old name.txt"), filepath.Join(dir, "renamed ü.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, "deleted.txt")); err != nil {
		t.Fatal(err)
	}
	writeTest(t, dir, "main.go", "package app\nfunc Version() string { return \"new\" }\n")
	writeTest(t, dir, "image.bin", "\x00new")
	gitTest(t, dir, "", "add", "-A")
	weird := "tab\tnewline\nquote\".txt"
	gitTest(t, dir, "", "config", "core.protectNTFS", "false")
	oid := gitTest(t, dir, "special path\n", "hash-object", "-w", "--stdin")
	gitTest(t, dir, "", "update-index", "--add", "--cacheinfo", "100644", oid, weird)
	head := commitIndex(t, dir)
	change, err := r.Analyze(ctx, base, "HEAD", false)
	if err != nil {
		t.Fatal(err)
	}
	if change.BaseCommit != base || change.HeadCommit != head {
		t.Fatalf("wrong immutable IDs: %+v", change)
	}
	if len(change.Files) != 5 {
		t.Fatalf("files=%+v", change.Files)
	}
	found := map[string]bool{}
	for _, f := range change.Files {
		found[f.Path] = true
		switch f.Path {
		case "renamed ü.txt":
			if f.Status != "R" || f.OldPath != "old name.txt" {
				t.Fatalf("rename=%+v", f)
			}
		case "image.bin":
			if !f.Binary {
				t.Fatal("binary not detected")
			}
		case "deleted.txt":
			if f.Status != "D" || f.Deletions != 1 {
				t.Fatalf("delete=%+v", f)
			}
		case "main.go":
			if f.Additions != 1 || f.Deletions != 1 || len(f.Hunks) != 1 {
				t.Fatalf("main=%+v", f)
			}
		}
	}
	if !found[weird] {
		t.Fatalf("unusual filename lost: %+v", found)
	}
	content, err := r.ReadFile(ctx, head, weird)
	if err != nil || string(content) != "special path\n" {
		t.Fatalf("read unusual file: %q %v", content, err)
	}
	// Worktree changes do not affect analysis of the frozen commit.
	writeTest(t, dir, "main.go", "uncommitted\n")
	content, err = r.ReadFile(ctx, head, "main.go")
	if err != nil || strings.Contains(string(content), "uncommitted") {
		t.Fatalf("commit read: %q %v", content, err)
	}
}

func TestSnapshotExactBlobsAndRefusal(t *testing.T) {
	dir, r := newTestRepo(t)
	ctx := context.Background()
	writeTest(t, dir, "nested/file.txt", "$Format:%H$\r\n")
	writeTest(t, dir, "ignored.txt", "must be exported\n")
	writeTest(t, dir, ".gitattributes", "nested/file.txt export-subst\nignored.txt export-ignore\n")
	base := commitTest(t, dir)
	dest := filepath.Join(t.TempDir(), "snapshot")
	if err := r.Snapshot(ctx, base, dest); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(dest, "nested/file.txt"))
	if err != nil || string(got) != "$Format:%H$\r\n" {
		t.Fatalf("snapshot transformed bytes: %q %v", got, err)
	}
	if _, err = os.Stat(filepath.Join(dest, "ignored.txt")); err != nil {
		t.Fatalf("export-ignore honored unexpectedly: %v", err)
	}
	if _, err = os.Stat(filepath.Join(dest, ".git")); !os.IsNotExist(err) {
		t.Fatal("Git metadata in snapshot")
	}
	if err = r.Snapshot(ctx, base, dest); err == nil {
		t.Fatal("snapshot overwrote nonempty directory")
	}
	linkOID := gitTest(t, dir, "../../outside\n", "hash-object", "-w", "--stdin")
	gitTest(t, dir, "", "update-index", "--add", "--cacheinfo", "120000", linkOID, "badlink")
	withLink := commitIndex(t, dir)
	if err = r.Snapshot(ctx, withLink, filepath.Join(t.TempDir(), "reject")); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlink snapshot: %v", err)
	}
}

func TestRefsMergeBaseMissingAndLimits(t *testing.T) {
	dir, r := newTestRepo(t)
	ctx := context.Background()
	writeTest(t, dir, "a.txt", "a\n")
	ancestor := commitTest(t, dir)
	gitTest(t, dir, "", "checkout", "-b", "feature")
	writeTest(t, dir, "feature.txt", "f\n")
	head := commitTest(t, dir)
	gitTest(t, dir, "", "checkout", "main")
	writeTest(t, dir, "main.txt", "m\n")
	base := commitTest(t, dir)
	change, err := r.Analyze(ctx, base, head, true)
	if err != nil {
		t.Fatal(err)
	}
	if change.BaseCommit != ancestor || len(change.Files) != 1 || change.Files[0].Path != "feature.txt" {
		t.Fatalf("merge base: %+v", change)
	}
	if _, err = r.Analyze(ctx, "--help", head, false); err == nil {
		t.Fatal("option revision accepted")
	}
	if _, err = r.ReadFile(ctx, head, "absent.txt"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing error=%v", err)
	}
	if _, err = r.ReadFile(ctx, "HEAD", "a.txt"); err == nil {
		t.Fatal("mutable ReadFile ref accepted")
	}
	if _, err = r.ReadFile(ctx, head, "../a.txt"); err == nil {
		t.Fatal("traversal accepted")
	}
	writeTest(t, dir, "large.txt", strings.Repeat("a", MaxFileBytes+1))
	largeCommit := commitTest(t, dir)
	if _, err = r.ReadFile(ctx, largeCommit, "large.txt"); !errors.Is(err, ErrLimit) {
		t.Fatalf("large error=%v", err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err = r.Analyze(canceled, base, head, false); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation=%v", err)
	}
}

func TestSafePath(t *testing.T) {
	for _, p := range []string{"../a", "/a", "a/../b", "a\\b", "C:/a", ".git/config", "a/.GIT/x", "a.", "a/CON.txt", "a/NUL", "a//b", "."} {
		if SafePath(p) == nil {
			t.Errorf("accepted %q", p)
		}
	}
	for _, p := range []string{"a/b.go", ".github/workflows/ci.yml", "dir/space ü.txt"} {
		if err := SafePath(p); err != nil {
			t.Errorf("rejected %q: %v", p, err)
		}
	}
}
func TestParsePatchNoNewlineAndModeOnly(t *testing.T) {
	names, err := parseNames([]byte("M\x00a\x00M\x00b\x00"))
	if err != nil {
		t.Fatal(err)
	}
	patch := []byte("diff --git a/a b/a\n--- a/a\n+++ b/a\n@@ -1 +1 @@\n-old\n\\ No newline at end of file\n+new\n\\ No newline at end of file\ndiff --git a/b b/b\nold mode 100644\nnew mode 100755\n")
	if err = parsePatch(patch, names); err != nil {
		t.Fatal(err)
	}
	if names[0].Additions != 1 || names[0].Deletions != 1 || len(names[1].Hunks) != 0 {
		t.Fatalf("parsed=%+v", names)
	}
}
func BenchmarkParsePatch(b *testing.B) {
	var source bytes.Buffer
	for i := 0; i < 1000; i++ {
		source.WriteString("diff --git a/file.go b/file.go\n--- a/file.go\n+++ b/file.go\n@@ -1,2 +1,2 @@\n package test\n-old\n+new\n")
	}
	data := source.Bytes()
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		files := make([]model.ChangedFile, 1000)
		if err := parsePatch(data, files); err != nil {
			b.Fatal(err)
		}
	}
}

func TestAnalyzeOverridesUserDiffIndicators(t *testing.T) {
	dir, r := newTestRepo(t)
	writeTest(t, dir, "a.txt", "same\nold\n")
	base := commitTest(t, dir)
	writeTest(t, dir, "a.txt", "same\nnew\n")
	head := commitTest(t, dir)
	for _, setting := range [][2]string{{"diff.outputIndicatorNew", ">"}, {"diff.outputIndicatorOld", "<"}, {"diff.outputIndicatorContext", "_"}, {"diff.noprefix", "true"}, {"diff.suppressBlankEmpty", "true"}} {
		gitTest(t, dir, "", "config", setting[0], setting[1])
	}
	change, err := r.Analyze(context.Background(), base, head, false)
	if err != nil {
		t.Fatal(err)
	}
	if change.Additions != 1 || change.Deletions != 1 {
		t.Fatalf("indicators altered parse: %+v", change)
	}
}

func TestAnalyzeFileTypeChange(t *testing.T) {
	dir, r := newTestRepo(t)
	writeTest(t, dir, "file.txt", "regular contents\n")
	base := commitTest(t, dir)
	oid := gitTest(t, dir, "target.txt", "hash-object", "-w", "--stdin")
	gitTest(t, dir, "", "update-index", "--add", "--cacheinfo", "120000", oid, "file.txt")
	head := commitIndex(t, dir)
	change, err := r.Analyze(context.Background(), base, head, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(change.Files) != 1 || change.Files[0].Status != "T" {
		t.Fatalf("type change=%+v", change)
	}
}

func TestParsePatchResourceLimit(t *testing.T) {
	patch := "diff --git a/a b/a\n--- a/a\n+++ b/a\n@@ -0,0 +1,250001 @@\n" + strings.Repeat("+x\n", maxPatchLines+1)
	if err := parsePatch([]byte(patch), []model.ChangedFile{{Path: "a", Status: "A"}}); !errors.Is(err, ErrLimit) {
		t.Fatalf("line budget: %v", err)
	}
}
