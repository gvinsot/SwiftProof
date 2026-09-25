package gitrepo

// Tree listing and blob reading from Git objects (F0c-owned, frozen). Snapshot,
// the symbol index (F6a) and the prepare input export (F8) read commits only
// through these two primitives, never through a second tree or blob reader.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// TreeEntry is one record of `git ls-tree -r -l`: Mode ("100644", "100755",
// "120000", "160000", ...), Type ("blob" or "commit"), the object ID and, for a
// blob, its size in bytes (-1 for a submodule commit, which has no size).
// Path is the repository-relative path exactly as Git records it; callers
// that open, write or report files by path must validate it with SafePath.
type TreeEntry struct {
	Path, Mode, Type, OID string
	Size                  int64
}

// Tree lists every entry of commit recursively with `git ls-tree -r -z -l`,
// under the same limits as Snapshot: at most 64 MiB of listing and 100,000
// entries. It reads Git objects only, never the working tree.
func (r *Repository) Tree(ctx context.Context, commit string) ([]TreeEntry, error) {
	if !validObjectID(commit) {
		return nil, errors.New("Tree requires a resolved commit identifier")
	}
	listing, err := r.git(ctx, maxGitOutput, "ls-tree", "-r", "-z", "-l", "--full-tree", commit)
	if err != nil {
		return nil, err
	}
	if bytes.Count(listing, []byte{0}) > maxTreeEntries {
		return nil, fmt.Errorf("tree contains over %d tracked files: %w", maxTreeEntries, ErrLimit)
	}
	var entries []TreeEntry
	for _, record := range bytes.Split(listing, []byte{0}) {
		if len(record) == 0 {
			continue
		}
		header, name, ok := strings.Cut(string(record), "\t")
		parts := strings.Fields(header)
		if !ok || name == "" || len(parts) != 4 || !validObjectID(parts[2]) || !validMode(parts[0]) {
			return nil, errors.New("invalid Git tree metadata")
		}
		e := TreeEntry{Path: name, Mode: parts[0], Type: parts[1], OID: parts[2], Size: -1}
		switch e.Type {
		case "blob":
			size, err := strconv.ParseInt(parts[3], 10, 64)
			if err != nil || size < 0 {
				return nil, errors.New("invalid Git tree object size")
			}
			e.Size = size
		case "commit":
			if parts[3] != "-" {
				return nil, errors.New("invalid Git tree object size")
			}
		default:
			return nil, fmt.Errorf("unsupported Git tree object type %q", e.Type)
		}
		entries = append(entries, e)
	}
	return entries, nil
}

func validMode(mode string) bool {
	if len(mode) != 6 {
		return false
	}
	for _, c := range mode {
		if c < '0' || c > '7' {
			return false
		}
	}
	return true
}

// ReadBlobs streams the blobs named by oids, in order, through one
// `git cat-file --batch` process and calls fn with each blob's content. A blob
// larger than limit bytes fails the whole call with ErrLimit before its content
// is read; callers that want to skip large files filter on TreeEntry.Size
// first. data is only valid during the call: fn must copy it to keep it. An
// error from fn stops the stream and is returned unchanged.
func (r *Repository) ReadBlobs(ctx context.Context, oids []string, limit int64, fn func(oid string, data []byte) error) error {
	if limit < 0 {
		return errors.New("ReadBlobs requires a non-negative size limit")
	}
	var requests strings.Builder
	for _, oid := range oids {
		if !validObjectID(oid) {
			return fmt.Errorf("invalid Git object identifier %q", oid)
		}
		requests.WriteString(oid)
		requests.WriteByte('\n')
	}
	if len(oids) == 0 {
		return nil
	}
	// cat-file --batch streams the exact blobs, honoring neither checkout filters
	// nor export attributes. Feeding object IDs also handles newlines in filenames.
	c := r.command(ctx, "cat-file", "--batch")
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
	var buffer []byte
	for _, oid := range oids {
		size, readErr := reader.header(oid)
		if readErr != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return readErr
		}
		if size > limit {
			return fmt.Errorf("blob %s: %w", oid, ErrLimit)
		}
		if int64(cap(buffer)) < size {
			buffer = make([]byte, size)
		}
		data := buffer[:size]
		if _, err = io.ReadFull(reader, data); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		if err = reader.separator(); err != nil {
			return err
		}
		if err = fn(oid, data); err != nil {
			return err
		}
	}
	err = c.Wait()
	complete = true
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil {
		return fmt.Errorf("git cat-file: %w: %s", err, stderr.String())
	}
	return nil
}
