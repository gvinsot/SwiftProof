package gitrepo

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/gvinsot/SwiftProof/app/internal/fsutil"
)

// treeFixture commits a tree with regular, executable, empty, nested, CRLF,
// non-ASCII and space-bearing files, plus a symlink and a submodule entry in a
// second commit. It returns the plain commit and the one with special entries.
func treeFixture(t *testing.T) (dir string, r *Repository, plain, special string) {
	t.Helper()
	dir, r = newTestRepo(t)
	files := map[string]string{
		"README.md":              "# fixture\n",
		"cmd/tool/main.go":       "package main\nfunc main() {}\n",
		"scripts/run.sh":         "#!/bin/sh\necho run\n",
		"data/crlf.txt":          "line one\r\nline two\r\n",
		"data/empty.txt":         "",
		"docs/space name.txt":    "spaces are kept\n",
		"docs/ümlaut.txt":        "non-ASCII path\n",
		"deep/a/b/c/d/leaf.json": `{"deep":true}`,
		"binary.bin":             "\x00\x01\x02\xff",
	}
	for p, content := range files {
		writeTest(t, dir, p, content)
	}
	gitTest(t, dir, "", "add", "-A")
	gitTest(t, dir, "", "update-index", "--chmod=+x", "scripts/run.sh")
	plain = commitIndex(t, dir)
	linkOID := gitTest(t, dir, "README.md", "hash-object", "-w", "--stdin")
	gitTest(t, dir, "", "update-index", "--add", "--cacheinfo", "120000", linkOID, "link")
	gitTest(t, dir, "", "update-index", "--add", "--cacheinfo", "160000", plain, "vendor/sub")
	special = commitIndex(t, dir)
	return dir, r, plain, special
}

func TestTreeListsEveryEntryWithModeTypeAndSize(t *testing.T) {
	dir, r, plain, special := treeFixture(t)
	ctx := context.Background()
	entries, err := r.Tree(ctx, special)
	if err != nil {
		t.Fatal(err)
	}
	byPath := map[string]TreeEntry{}
	for _, e := range entries {
		if _, dup := byPath[e.Path]; dup {
			t.Fatalf("duplicate entry %q", e.Path)
		}
		byPath[e.Path] = e
	}
	if len(entries) != 11 {
		t.Fatalf("got %d entries: %+v", len(entries), entries)
	}
	for path, want := range map[string]struct {
		mode, typ string
		size      int64
	}{
		"README.md":           {"100644", "blob", 10},
		"scripts/run.sh":      {"100755", "blob", int64(len("#!/bin/sh\necho run\n"))},
		"data/empty.txt":      {"100644", "blob", 0},
		"data/crlf.txt":       {"100644", "blob", int64(len("line one\r\nline two\r\n"))},
		"docs/space name.txt": {"100644", "blob", int64(len("spaces are kept\n"))},
		"docs/ümlaut.txt":     {"100644", "blob", int64(len("non-ASCII path\n"))},
		"link":                {"120000", "blob", int64(len("README.md"))},
		"vendor/sub":          {"160000", "commit", -1},
	} {
		got, ok := byPath[path]
		if !ok {
			t.Fatalf("missing entry %q in %+v", path, entries)
		}
		if got.Mode != want.mode || got.Type != want.typ || got.Size != want.size || !validObjectID(got.OID) {
			t.Errorf("%s: got %+v, want mode %s type %s size %d", path, got, want.mode, want.typ, want.size)
		}
	}
	if oid := gitTest(t, dir, "", "rev-parse", plain+":README.md"); byPath["README.md"].OID != oid {
		t.Errorf("README.md object %s, want %s", byPath["README.md"].OID, oid)
	}
	if byPath["vendor/sub"].OID != plain {
		t.Errorf("submodule entry records %s, want %s", byPath["vendor/sub"].OID, plain)
	}
	// Paths are returned as Git records them; the caller validates.
	for _, e := range entries {
		if err := SafePath(e.Path); err != nil {
			t.Errorf("fixture path %q unexpectedly unsafe: %v", e.Path, err)
		}
	}
}

func TestTreeRefusesUnresolvedCommitsAndWrongObjects(t *testing.T) {
	_, r, plain, _ := treeFixture(t)
	ctx := context.Background()
	for _, commit := range []string{"", "HEAD", "main", "--output=x", strings.Repeat("g", 40)} {
		if _, err := r.Tree(ctx, commit); err == nil {
			t.Errorf("Tree accepted unresolved commit %q", commit)
		}
	}
	if _, err := r.Tree(ctx, strings.Repeat("0", 40)); err == nil {
		t.Error("Tree listed a missing commit")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := r.Tree(cancelled, plain); err == nil {
		t.Error("Tree ignored a cancelled context")
	}
}

func TestReadBlobsStreamsExactBytesInOrder(t *testing.T) {
	dir, r, plain, _ := treeFixture(t)
	ctx := context.Background()
	entries, err := r.Tree(ctx, plain)
	if err != nil {
		t.Fatal(err)
	}
	var oids []string
	want := map[string]string{}
	for _, e := range entries {
		oids = append(oids, e.OID)
		b, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(e.Path)))
		if err != nil {
			t.Fatal(err)
		}
		want[e.OID] = string(b)
	}
	oids = append(oids, oids[0]) // a repeated object is streamed again
	var got []string
	var order []string
	err = r.ReadBlobs(ctx, oids, 1<<20, func(oid string, data []byte) error {
		order = append(order, oid)
		got = append(got, string(data)) // copies: data is only valid during the call
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(order, ",") != strings.Join(oids, ",") {
		t.Fatalf("blobs streamed out of order: %v", order)
	}
	for i, oid := range oids {
		if got[i] != want[oid] {
			t.Errorf("blob %s: got %q, want %q", oid, got[i], want[oid])
		}
	}
}

func TestReadBlobsLimitsAndErrors(t *testing.T) {
	_, r, plain, _ := treeFixture(t)
	ctx := context.Background()
	entries, err := r.Tree(ctx, plain)
	if err != nil {
		t.Fatal(err)
	}
	var small, large TreeEntry
	for _, e := range entries {
		if e.Path == "binary.bin" {
			small = e
		}
		if e.Path == "cmd/tool/main.go" {
			large = e
		}
	}
	calls := 0
	err = r.ReadBlobs(ctx, []string{small.OID, large.OID}, small.Size, func(string, []byte) error { calls++; return nil })
	if !errors.Is(err, ErrLimit) || calls != 1 {
		t.Fatalf("an oversized blob was not refused before delivery: calls=%d err=%v", calls, err)
	}
	stop := errors.New("stop")
	calls = 0
	if err = r.ReadBlobs(ctx, []string{small.OID, large.OID}, 1<<20, func(string, []byte) error { calls++; return stop }); err != stop || calls != 1 {
		t.Fatalf("callback error not returned unchanged: calls=%d err=%v", calls, err)
	}
	if err = r.ReadBlobs(ctx, []string{"not-an-oid"}, 1<<20, func(string, []byte) error { return nil }); err == nil {
		t.Fatal("invalid object ID accepted")
	}
	if err = r.ReadBlobs(ctx, []string{strings.Repeat("0", 40)}, 1<<20, func(string, []byte) error { return nil }); err == nil {
		t.Fatal("missing object read without error")
	}
	// A tree object is not a blob.
	treeOID := gitTest(t, r.Root, "", "rev-parse", plain+"^{tree}")
	if err = r.ReadBlobs(ctx, []string{treeOID}, 1<<20, func(string, []byte) error { return nil }); err == nil {
		t.Fatal("a tree object was streamed as a blob")
	}
	if err = r.ReadBlobs(ctx, nil, 1<<20, func(string, []byte) error { t.Fatal("callback without blobs"); return nil }); err != nil {
		t.Fatal(err)
	}
	if err = r.ReadBlobs(ctx, []string{small.OID}, -1, func(string, []byte) error { return nil }); err == nil {
		t.Fatal("negative limit accepted")
	}
}

// legacySnapshot is Snapshot exactly as it was before it was rebuilt on Tree
// and ReadBlobs (commit 27c014b). It is the oracle for the byte-for-byte test.
func legacySnapshot(r *Repository, ctx context.Context, commit, dest string) error {
	if !validObjectID(commit) {
		return errors.New("Snapshot requires a resolved commit identifier")
	}
	listing, err := r.git(ctx, maxGitOutput, "ls-tree", "-r", "-z", commit)
	if err != nil {
		return err
	}
	if bytes.Count(listing, []byte{0}) > maxTreeEntries {
		return fmt.Errorf("snapshot contains over %d tracked files: %w", maxTreeEntries, ErrLimit)
	}
	type entry struct {
		name, oid  string
		executable bool
	}
	var entries []entry
	for _, record := range bytes.Split(listing, []byte{0}) {
		if len(record) == 0 {
			continue
		}
		header, name, ok := strings.Cut(string(record), "\t")
		parts := strings.Fields(header)
		if !ok || len(parts) != 3 || !validObjectID(parts[2]) {
			return errors.New("invalid Git tree metadata")
		}
		if err = SafePath(name); err != nil {
			return err
		}
		if parts[1] != "blob" || parts[0] != "100644" && parts[0] != "100755" {
			return fmt.Errorf("snapshot rejects symlink, submodule, or unsupported mode %s at %q", parts[0], name)
		}
		entries = append(entries, entry{name, parts[2], parts[0] == "100755"})
	}
	abs, err := filepath.Abs(dest)
	if err != nil {
		return err
	}
	for p := abs; ; p = filepath.Dir(p) {
		info, e := os.Lstat(p)
		if e == nil && info.Mode()&os.ModeSymlink != 0 && !fsutil.IsSystemAlias(p) {
			return fmt.Errorf("snapshot destination has symlink ancestor %q", p)
		}
		if e != nil && !os.IsNotExist(e) {
			return e
		}
		if filepath.Dir(p) == p {
			break
		}
	}
	if items, e := os.ReadDir(abs); e == nil && len(items) != 0 {
		return errors.New("snapshot destination must be empty")
	} else if e != nil && !os.IsNotExist(e) {
		return e
	}
	if err = os.MkdirAll(abs, 0700); err != nil {
		return err
	}
	if len(entries) == 0 {
		return nil
	}
	c := r.command(ctx, "cat-file", "--batch")
	var requests strings.Builder
	for _, e := range entries {
		requests.WriteString(e.oid)
		requests.WriteByte('\n')
	}
	c.Stdin = strings.NewReader(requests.String())
	stderr := &limitedBuffer{limit: 8192}
	c.Stderr = stderr
	stdout, err := c.StdoutPipe()
	if err != nil {
		return err
	}
	if err = c.Start(); err != nil {
		return err
	}
	complete := false
	defer func() {
		if !complete {
			_ = c.Process.Kill()
			_ = c.Wait()
		}
	}()
	reader := newBlobReader(stdout)
	var total int64
	for _, e := range entries {
		size, readErr := reader.header(e.oid)
		if readErr != nil {
			return readErr
		}
		if size > maxSnapshotFile || size > maxSnapshotBytes-total {
			return fmt.Errorf("snapshot %q: %w", e.name, ErrLimit)
		}
		total += size
		target := filepath.Join(abs, filepath.FromSlash(e.name))
		if err = os.MkdirAll(filepath.Dir(target), 0700); err != nil {
			return err
		}
		mode := os.FileMode(0600)
		if e.executable {
			mode = 0700
		}
		f, eopen := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
		if eopen != nil {
			return eopen
		}
		_, copyErr := io.CopyN(f, reader, size)
		closeErr := f.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
		if err = reader.separator(); err != nil {
			return err
		}
	}
	err = c.Wait()
	complete = true
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil {
		return fmt.Errorf("snapshot: %w: %s", err, stderr.String())
	}
	return nil
}

// snapshotListing describes every path below root: kind, permission bits and
// exact content, so two exports can be compared byte for byte.
func snapshotListing(t *testing.T, root string) string {
	t.Helper()
	var lines []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		perm := info.Mode().Perm()
		if runtime.GOOS == "windows" {
			perm = 0 // Windows does not keep Unix permission bits
		}
		if d.IsDir() {
			lines = append(lines, fmt.Sprintf("dir %s %o", filepath.ToSlash(rel), perm))
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		lines = append(lines, fmt.Sprintf("file %s %o %q", filepath.ToSlash(rel), perm, b))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n")
}

func TestSnapshotUnchangedByteForByte(t *testing.T) {
	_, r, plain, special := treeFixture(t)
	ctx := context.Background()
	legacy, rebuilt := filepath.Join(t.TempDir(), "legacy"), filepath.Join(t.TempDir(), "rebuilt")
	if err := legacySnapshot(r, ctx, plain, legacy); err != nil {
		t.Fatal(err)
	}
	if err := r.Snapshot(ctx, plain, rebuilt); err != nil {
		t.Fatal(err)
	}
	want, got := snapshotListing(t, legacy), snapshotListing(t, rebuilt)
	if want != got {
		t.Fatalf("Snapshot output changed:\nlegacy:\n%s\nrebuilt:\n%s", want, got)
	}
	if !strings.Contains(got, `file data/crlf.txt`) || !strings.Contains(got, `"line one\r\nline two\r\n"`) {
		t.Fatalf("fixture content missing from the export:\n%s", got)
	}
	if runtime.GOOS != "windows" && !strings.Contains(got, "file scripts/run.sh 700") {
		t.Fatalf("executable mode not preserved:\n%s", got)
	}
	// Both refuse the symlink and submodule entries, before writing anything.
	for name, snapshot := range map[string]func(context.Context, string, string) error{
		"legacy":  func(ctx context.Context, c, d string) error { return legacySnapshot(r, ctx, c, d) },
		"rebuilt": r.Snapshot,
	} {
		dest := filepath.Join(t.TempDir(), "special")
		err := snapshot(ctx, special, dest)
		if err == nil || !strings.Contains(err.Error(), "snapshot rejects symlink, submodule, or unsupported mode") {
			t.Fatalf("%s snapshot of special entries: %v", name, err)
		}
		if _, statErr := os.Stat(dest); !os.IsNotExist(statErr) {
			t.Errorf("%s snapshot created its destination before refusing", name)
		}
	}
	// A non-empty destination is refused by both.
	if err := r.Snapshot(ctx, plain, rebuilt); err == nil || !strings.Contains(err.Error(), "must be empty") {
		t.Fatalf("rebuilt Snapshot overwrote a non-empty destination: %v", err)
	}
}

func TestSnapshotEmptyTreeAndCancellation(t *testing.T) {
	dir, r := newTestRepo(t)
	ctx := context.Background()
	gitTest(t, dir, "", "commit", "--allow-empty", "--no-gpg-sign", "-m", "empty")
	empty := gitTest(t, dir, "", "rev-parse", "HEAD")
	dest := filepath.Join(t.TempDir(), "empty")
	if err := r.Snapshot(ctx, empty, dest); err != nil {
		t.Fatal(err)
	}
	if items, err := os.ReadDir(dest); err != nil || len(items) != 0 {
		t.Fatalf("empty tree export: %v %v", items, err)
	}
	_, r2, plain, _ := treeFixture(t)
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err := r2.Snapshot(cancelled, plain, filepath.Join(t.TempDir(), "cancelled")); err == nil {
		t.Fatal("Snapshot ignored a cancelled context")
	}
}
