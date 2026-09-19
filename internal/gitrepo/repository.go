// Package gitrepo reads immutable Git changes without executing repository code.
package gitrepo

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/gvinsot/SwiftProof/internal/fsutil"
	"github.com/gvinsot/SwiftProof/internal/model"
)

const (
	MaxFileBytes     = 2 << 20
	maxGitOutput     = 64 << 20
	maxSnapshotFile  = 512 << 20
	maxSnapshotBytes = 2 << 30
	maxTreeEntries   = 100000
	maxPatchLines    = 250000
)

var ErrLimit = errors.New("analysis size limit exceeded")
var ErrNotFound = errors.New("file not present in commit")

type Repository struct{ Root string }

// Open locates the worktree root without changing its files or index.
func Open(ctx context.Context, dir string) (*Repository, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	r := &Repository{Root: abs}
	b, err := r.git(ctx, 4096, "rev-parse", "--show-toplevel")
	if err != nil {
		return nil, fmt.Errorf("open Git repository: %w", err)
	}
	r.Root = strings.TrimSuffix(strings.TrimSuffix(string(b), "\n"), "\r")
	return r, nil
}

func (r *Repository) command(ctx context.Context, args ...string) *exec.Cmd {
	all := append([]string{"-c", "core.quotepath=true", "-c", "core.pager=cat", "-c", "core.fsmonitor=false", "-c", "diff.suppressBlankEmpty=false", "-c", "diff.outputIndicatorNew=+", "-c", "diff.outputIndicatorOld=-", "-c", "diff.outputIndicatorContext= ", "-C", r.Root}, args...)
	c := exec.CommandContext(ctx, "git", all...)
	// Do not let a caller's Git environment redirect the repository or load objects elsewhere.
	for _, e := range os.Environ() {
		name, _, _ := strings.Cut(e, "=")
		if !strings.HasPrefix(strings.ToUpper(name), "GIT_") {
			c.Env = append(c.Env, e)
		}
	}
	c.Env = append(c.Env, "GIT_TERMINAL_PROMPT=0", "GIT_OPTIONAL_LOCKS=0", "LC_ALL=C")
	return c
}

type limitedBuffer struct {
	buffer   bytes.Buffer
	limit    int
	exceeded bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if len(p) > b.limit-b.buffer.Len() {
		b.exceeded = true
		return 0, ErrLimit
	}
	return b.buffer.Write(p)
}
func (b *limitedBuffer) Bytes() []byte  { return b.buffer.Bytes() }
func (b *limitedBuffer) String() string { return b.buffer.String() }
func (r *Repository) git(ctx context.Context, limit int, args ...string) ([]byte, error) {
	c := r.command(ctx, args...)
	out, stderr := &limitedBuffer{limit: limit}, &limitedBuffer{limit: 8192}
	c.Stdout, c.Stderr = out, stderr
	err := c.Run()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if out.exceeded || stderr.exceeded {
		return nil, ErrLimit
	}
	if err != nil {
		if args[0] == "show" && (strings.Contains(stderr.String(), "does not exist in") || strings.Contains(stderr.String(), "exists on disk, but not in")) {
			return nil, fmt.Errorf("%w: %s", ErrNotFound, strings.TrimSpace(stderr.String()))
		}
		return nil, fmt.Errorf("git %s: %w: %s", args[0], err, strings.TrimSpace(stderr.String()))
	}
	return out.Bytes(), nil
}

func (r *Repository) resolve(ctx context.Context, ref string) (string, error) {
	if ref == "" || strings.HasPrefix(ref, "-") || strings.ContainsAny(ref, "\x00\r\n") {
		return "", fmt.Errorf("invalid Git revision %q", ref)
	}
	b, err := r.git(ctx, 1024, "rev-parse", "--verify", "--end-of-options", ref+"^{commit}")
	if err != nil {
		return "", err
	}
	id := strings.TrimSpace(string(b))
	if !validObjectID(id) {
		return "", errors.New("Git returned an invalid commit identifier")
	}
	return id, nil
}

func validObjectID(id string) bool {
	if len(id) != 40 && len(id) != 64 {
		return false
	}
	for _, c := range id {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// Analyze resolves both refs first. With mergeBase, BaseCommit is their common ancestor.
func (r *Repository) Analyze(ctx context.Context, base, head string, mergeBase bool) (model.Change, error) {
	change := model.Change{BaseRef: base, HeadRef: head, Files: []model.ChangedFile{}}
	var err error
	if change.BaseCommit, err = r.resolve(ctx, base); err != nil {
		return change, fmt.Errorf("base: %w", err)
	}
	if change.HeadCommit, err = r.resolve(ctx, head); err != nil {
		return change, fmt.Errorf("head: %w", err)
	}
	if mergeBase {
		b, e := r.git(ctx, 1024, "merge-base", "--all", change.BaseCommit, change.HeadCommit)
		if e != nil {
			return change, fmt.Errorf("merge base: %w", e)
		}
		ids := strings.Fields(string(b))
		if len(ids) != 1 || !validObjectID(ids[0]) {
			return change, errors.New("comparison has multiple merge bases; select an explicit base commit")
		}
		change.BaseCommit = ids[0]
	}
	common := []string{"diff", "--no-ext-diff", "--no-textconv", "--no-color", "--no-relative", "--find-renames=50%", "-l1000", "--ignore-submodules=none"}
	args := append(append([]string{}, common...), "--name-status", "-z", change.BaseCommit, change.HeadCommit, "--")
	metadata, err := r.git(ctx, maxGitOutput, args...)
	if err != nil {
		return change, err
	}
	if change.Files, err = parseNames(metadata); err != nil {
		return change, err
	}
	if len(change.Files) == 0 {
		return change, nil
	}
	args = append(append([]string{}, common...), "--patch", "--unified=3", "--src-prefix=a/", "--dst-prefix=b/", change.BaseCommit, change.HeadCommit, "--")
	patch, err := r.git(ctx, maxGitOutput, args...)
	if err != nil {
		return change, err
	}
	if err = parsePatch(patch, change.Files); err != nil {
		return change, err
	}
	for _, f := range change.Files {
		change.Additions += f.Additions
		change.Deletions += f.Deletions
	}
	return change, nil
}

func parseNames(data []byte) ([]model.ChangedFile, error) {
	files := []model.ChangedFile{}
	if len(data) == 0 {
		return files, nil
	}
	if bytes.Count(data, []byte{0}) > maxTreeEntries*3 {
		return nil, fmt.Errorf("Git file metadata: %w", ErrLimit)
	}
	parts := bytes.Split(data, []byte{0})
	if len(parts[len(parts)-1]) != 0 {
		return nil, errors.New("unterminated Git path metadata")
	}
	parts = parts[:len(parts)-1]
	for i := 0; i < len(parts); {
		status := string(parts[i])
		i++
		if status == "" || i >= len(parts) {
			return nil, errors.New("invalid Git status metadata")
		}
		f := model.ChangedFile{Status: status[:1], Path: string(parts[i]), Hunks: []model.Hunk{}}
		i++
		if f.Status == "R" || f.Status == "C" {
			if i >= len(parts) {
				return nil, errors.New("missing renamed Git path")
			}
			f.OldPath = f.Path
			f.Path = string(parts[i])
			i++
		}
		files = append(files, f)
		if len(files) > maxTreeEntries {
			return nil, fmt.Errorf("changed file count: %w", ErrLimit)
		}
	}
	return files, nil
}

func parsePatch(data []byte, files []model.ChangedFile) error {
	index := -1
	previousHeader := ""
	typeChangeSecondPart := false
	var current *model.Hunk
	oldLine, newLine := 0, 0
	parsedLines := 0
	remaining := string(data)
	for len(remaining) > 0 {
		line, rest, _ := strings.Cut(remaining, "\n")
		remaining = rest
		if strings.HasPrefix(line, "diff --git ") {
			// Git represents a file-type change as a deletion followed by an
			// addition, each with the same diff header, but one T metadata entry.
			if index >= 0 && files[index].Status == "T" && line == previousHeader && !typeChangeSecondPart {
				typeChangeSecondPart = true
			} else {
				index++
				typeChangeSecondPart = false
			}
			previousHeader = line
			current = nil
			if index >= len(files) {
				return errors.New("Git patch and metadata disagree")
			}
			continue
		}
		if index < 0 {
			continue
		}
		f := &files[index]
		if strings.HasPrefix(line, "Binary files ") || line == "GIT binary patch" {
			f.Binary = true
			continue
		}
		if strings.HasPrefix(line, "@@ ") {
			h, err := parseHunkHeader(line)
			if err != nil {
				return err
			}
			f.Hunks = append(f.Hunks, h)
			current = &f.Hunks[len(f.Hunks)-1]
			oldLine, newLine = h.OldStart, h.NewStart
			continue
		}
		if current == nil || len(line) == 0 || line[0] == '\\' {
			continue
		}
		d := model.DiffLine{Content: line[1:]}
		switch line[0] {
		case '+':
			d.Kind = "add"
			d.NewLine = newLine
			newLine++
			f.Additions++
		case '-':
			d.Kind = "delete"
			d.OldLine = oldLine
			oldLine++
			f.Deletions++
		case ' ':
			d.Kind = "context"
			d.OldLine = oldLine
			d.NewLine = newLine
			oldLine++
			newLine++
		default:
			return fmt.Errorf("invalid Git patch line %q", line)
		}
		current.Lines = append(current.Lines, d)
		parsedLines++
		if parsedLines > maxPatchLines {
			return fmt.Errorf("diff contains over %d lines: %w", maxPatchLines, ErrLimit)
		}
	}
	if index+1 != len(files) {
		return errors.New("Git patch and metadata file counts disagree")
	}
	return nil
}

func parseHunkHeader(line string) (model.Hunk, error) {
	h := model.Hunk{Lines: []model.DiffLine{}}
	fields := strings.Fields(line)
	if len(fields) < 4 || fields[0] != "@@" || fields[3] != "@@" {
		return h, fmt.Errorf("invalid Git hunk %q", line)
	}
	a, b, err := parseRange(fields[1], '-')
	if err != nil {
		return h, err
	}
	h.OldStart, h.OldLines = a, b
	a, b, err = parseRange(fields[2], '+')
	h.NewStart, h.NewLines = a, b
	return h, err
}
func parseRange(s string, prefix byte) (int, int, error) {
	if len(s) < 2 || s[0] != prefix {
		return 0, 0, errors.New("invalid hunk range")
	}
	a, b, hasCount := strings.Cut(s[1:], ",")
	start, err := strconv.Atoi(a)
	if err != nil || start < 0 {
		return 0, 0, errors.New("invalid hunk start")
	}
	count := 1
	if hasCount {
		count, err = strconv.Atoi(b)
	}
	if err != nil || count < 0 {
		return 0, 0, errors.New("invalid hunk length")
	}
	return start, count, nil
}

// SafePath validates portable repository paths used for file reads and exports.
func SafePath(p string) error {
	if p == "" || strings.ContainsAny(p, "\\\x00:") || strings.HasPrefix(p, "/") || path.Clean(p) != p {
		return fmt.Errorf("unsafe repository path %q", p)
	}
	for _, part := range strings.Split(p, "/") {
		if part == "." || part == ".." || strings.EqualFold(part, ".git") || strings.TrimRight(part, " .") != part {
			return fmt.Errorf("unsafe repository path %q", p)
		}
		stem := strings.ToUpper(strings.SplitN(part, ".", 2)[0])
		if stem == "CON" || stem == "PRN" || stem == "AUX" || stem == "NUL" || len(stem) == 4 && (strings.HasPrefix(stem, "COM") || strings.HasPrefix(stem, "LPT")) && stem[3] >= '1' && stem[3] <= '9' {
			return fmt.Errorf("unsafe portable repository path %q", p)
		}
	}
	return nil
}

// ReadFile reads at most MaxFileBytes from a commit, never from the working tree.
func (r *Repository) ReadFile(ctx context.Context, commit, file string) ([]byte, error) {
	if err := SafePath(file); err != nil {
		return nil, err
	}
	if !validObjectID(commit) {
		return nil, errors.New("ReadFile requires a resolved commit identifier")
	}
	return r.git(ctx, MaxFileBytes, "show", commit+":"+file)
}

// Snapshot exports regular tracked files into an empty directory. Symlinks and
// submodules are rejected, as are files >512 MiB and snapshots >2 GiB. Git archive
// export-ignore/export-subst attributes are deliberately bypassed via tree blobs.
func (r *Repository) Snapshot(ctx context.Context, commit, dest string) error {
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
	// cat-file --batch streams the exact blobs, honoring neither checkout filters
	// nor export attributes. Feeding object IDs also handles newlines in filenames.
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

type blobReader struct{ *bufio.Reader }

func newBlobReader(r io.Reader) *blobReader { return &blobReader{bufio.NewReader(r)} }
func (r *blobReader) header(oid string) (int64, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return 0, err
	}
	fields := strings.Fields(line)
	if len(fields) != 3 || fields[0] != oid || fields[1] != "blob" {
		return 0, errors.New("invalid Git blob stream header")
	}
	size, err := strconv.ParseInt(fields[2], 10, 64)
	if err != nil || size < 0 {
		return 0, errors.New("invalid Git blob size")
	}
	return size, nil
}
func (r *blobReader) separator() error {
	b, err := r.ReadByte()
	if err != nil {
		return err
	}
	if b != '\n' {
		return errors.New("invalid Git blob separator")
	}
	return nil
}
