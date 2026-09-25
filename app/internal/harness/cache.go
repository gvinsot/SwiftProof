package harness

// F0 stub of the execution cache state (F7a owns this file). The consult and
// store point, replay, agreement counting and eviction live in run.go and are
// complete; F7a replaces keyFor, confirmBaseline and Execution, and may add
// fields and functions. run.go relies on the fields and methods declared
// here: execState.cache, keyFor and preimage (keyFor records the preimage of
// every key it returns; run.go stores it on each new entry). Execution must
// report h.cacheCountersLocked(), the harness counters plus Stats().

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/gvinsot/SwiftProof/app/internal/model"
)

type execState struct {
	cache     ExecutionCache
	preimages map[string]json.RawMessage // key -> the canonical preimage keyFor hashed
}

// newExecState stores opts.Cache and validates opts.Parallel. It makes no
// Docker call; the stub never probes or pins the image.
func newExecState(opts Options) (execState, error) {
	if opts.Parallel < 0 || opts.Parallel > 4 {
		return execState{}, fmt.Errorf("parallel must be between 1 and 4, got %d", opts.Parallel)
	}
	return execState{cache: opts.Cache}, nil
}

// stubKeyInputs is the canonical preimage of the stub key. It holds hashes
// only, never raw argv or file contents.
type stubKeyInputs struct {
	Schema         string `json:"schema"`
	Kind           string `json:"kind"`
	TreeSHA256     string `json:"tree_sha256"`
	ArgvSHA256     string `json:"argv_sha256"`
	ScriptSHA256   string `json:"script_sha256"`
	TimeoutMS      int64  `json:"timeout_ms"`
	MaxOutputBytes int    `json:"max_output_bytes"`
}

// keyFor returns the cache key of an eligible run, or the reason it cannot be
// keyed. The stub key is deterministic for tests: sha256 of the kind, a
// manifest of every regular file under dir (relative path, executable bit,
// size and sha256, so the files a caller staged are included), the argv, the
// wrapper script, the effective per-run timeout and the output limit. It is
// stricter than F7a's pristine-tree rule: any change under dir changes the key.
func (s *execState) keyFor(h *Harness, kind, dir string, argv []string, script string, timeout time.Duration) (key, uncacheableReason string) {
	tree, err := stubTreeDigest(dir)
	if err != nil {
		return "", "the baseline tree could not be hashed: " + Redact(err.Error())
	}
	argvJSON, err := json.Marshal(argv)
	if err != nil {
		return "", "the command could not be encoded"
	}
	raw, err := json.Marshal(stubKeyInputs{Schema: "swiftproof-execcache-stub/v1", Kind: kind, TreeSHA256: tree, ArgvSHA256: sha256Hex(argvJSON), ScriptSHA256: sha256Hex([]byte(script)), TimeoutMS: timeout.Milliseconds(), MaxOutputBytes: h.opts.MaxOutputBytes})
	if err != nil {
		return "", "the key preimage could not be encoded"
	}
	key = sha256Hex(raw)
	if s.preimages == nil {
		s.preimages = map[string]json.RawMessage{}
	}
	s.preimages[key] = raw
	return key, ""
}

// preimage returns the canonical preimage keyFor hashed into key, or nil when
// this harness did not compute key. run.go stores it on every new entry so the
// store can recompute the key from what it holds.
func (s *execState) preimage(key string) json.RawMessage {
	if raw, ok := s.preimages[key]; ok {
		return append(json.RawMessage(nil), raw...)
	}
	return nil
}

// confirmBaseline re-runs a replayed baseline live before a reproduction is
// recorded. The stub returns its inputs unchanged; report.Finalize refuses
// REPRODUCED on a replayed base check regardless.
func (h *Harness) confirmBaseline(ctx context.Context, runner, path string, names, command []string, base model.Check) (model.Check, string, string) {
	return base, model.StatusReproduced, ""
}

// Execution summarizes the cache, parallelism and budget. The stub returns the
// cache counters (cacheCountersLocked) and Budget(), and leaves the rest zero.
func (h *Harness) Execution() model.Execution {
	h.mu.Lock()
	defer h.mu.Unlock()
	return model.Execution{Cache: h.cacheCountersLocked(), Budget: h.budgetLocked()}
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// stubTreeDigest hashes a manifest of every regular file under dir in lexical
// order. A symlink or special file, or a tree beyond the snapshot copy limits,
// cannot be keyed.
func stubTreeDigest(dir string) (string, error) {
	manifest := sha256.New()
	files := 0
	var total int64
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			return errors.New("the tree contains a symlink or special file")
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		files++
		total += info.Size()
		if files > 100000 || total > 512*1024*1024 {
			return errors.New("the tree exceeds the manifest limits")
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		content := sha256.New()
		_, err = io.Copy(content, f)
		closeErr := f.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
		executable := 0
		if info.Mode()&0111 != 0 {
			executable = 1
		}
		fmt.Fprintf(manifest, "%q %d %d %x\n", filepath.ToSlash(rel), executable, info.Size(), content.Sum(nil))
		return nil
	})
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(manifest.Sum(nil)), nil
}
