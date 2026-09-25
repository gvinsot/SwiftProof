// Package dockerutil inspects the local Docker daemon and its images through the
// docker CLI. It never starts a container, never pulls, and passes arguments
// without a shell. Every call is bounded in time by its context and in size by
// an explicit output limit.
package dockerutil

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"regexp"
	"strings"
	"unicode/utf8"
)

// Image is what SwiftProof reads from `docker image inspect`.
type Image struct {
	ID, OS, Architecture string
	Size                 int64
	Labels               map[string]string
	Layers               []string
	Env                  []string
}

// Info is what SwiftProof reads from `docker info`.
type Info struct {
	ServerVersion, OSType, Architecture string
	NCPU                                int
	MemTotal                            int64
}

// Runner executes the docker CLI with args and returns its standard output
// (at most stdoutLimit bytes, else an error) and a bounded standard error.
type Runner func(ctx context.Context, args []string, stdoutLimit int) (stdout, stderr []byte, err error)

// inspectLimit bounds the JSON of one inspect or info call.
const inspectLimit = 4 << 20

// stderrLimit bounds the standard error kept from one docker call.
const stderrLimit = 8 << 10

// ErrOutputLimit reports docker output larger than the caller allowed.
var ErrOutputLimit = errors.New("docker output exceeds its size limit")

// DefaultRunner runs exec.CommandContext("docker", args...): no shell, no -i/-t,
// no standard input, standard output bounded by stdoutLimit and standard error
// by 8 KiB.
var DefaultRunner Runner = runDocker

func runDocker(ctx context.Context, args []string, stdoutLimit int) ([]byte, []byte, error) {
	for _, arg := range args {
		if arg == "-i" || arg == "-t" || arg == "-it" || arg == "--interactive" || arg == "--tty" {
			return nil, nil, fmt.Errorf("docker argument %q is not allowed", arg)
		}
	}
	cmd := exec.CommandContext(ctx, "docker", args...)
	stdout := &limitWriter{limit: stdoutLimit}
	stderr := &limitWriter{limit: stderrLimit, drop: true}
	cmd.Stdin = nil
	cmd.Stdout, cmd.Stderr = stdout, stderr
	err := cmd.Run()
	if ctx.Err() != nil {
		return nil, stderr.Bytes(), ctx.Err()
	}
	if stdout.exceeded {
		return nil, stderr.Bytes(), ErrOutputLimit
	}
	return stdout.Bytes(), stderr.Bytes(), err
}

// limitWriter keeps at most limit bytes. Past the limit it either fails the
// write (standard output: the result would be incomplete) or drops the excess
// (standard error: diagnostics only).
type limitWriter struct {
	buf      bytes.Buffer
	limit    int
	drop     bool
	exceeded bool
}

func (w *limitWriter) Write(p []byte) (int, error) {
	remaining := w.limit - w.buf.Len()
	if len(p) > remaining {
		w.exceeded = true
		if !w.drop {
			return 0, ErrOutputLimit
		}
		if remaining > 0 {
			w.buf.Write(p[:remaining])
		}
		return len(p), nil
	}
	return w.buf.Write(p)
}

func (w *limitWriter) Bytes() []byte { return w.buf.Bytes() }

var imageIDPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// ValidImageID reports whether id is a full local image ID: ^sha256:[0-9a-f]{64}$.
func ValidImageID(id string) bool { return imageIDPattern.MatchString(id) }

// validRef refuses a reference the docker CLI could read as an option or that
// carries whitespace or control characters.
func validRef(ref string) error {
	if ref == "" || len(ref) > 512 || strings.HasPrefix(ref, "-") {
		return fmt.Errorf("invalid image reference %q", ref)
	}
	for _, r := range ref {
		if r <= ' ' || r == 0x7f {
			return fmt.Errorf("invalid image reference %q", ref)
		}
	}
	return nil
}

// InspectImage runs `image inspect --format {{json .}} REF` (≤4 MiB of output).
// found is false, with a nil error, when Docker reports that no such image
// exists locally. The returned ID is always a valid full image ID.
func InspectImage(ctx context.Context, run Runner, ref string) (Image, bool, error) {
	if err := validRef(ref); err != nil {
		return Image{}, false, err
	}
	if run == nil {
		run = DefaultRunner
	}
	stdout, stderr, err := run(ctx, []string{"image", "inspect", "--format", "{{json .}}", ref}, inspectLimit)
	if err != nil {
		if ctx.Err() == nil && strings.Contains(strings.ToLower(string(stderr)), "no such image") {
			return Image{}, false, nil
		}
		return Image{}, false, commandError("docker image inspect", err, stderr)
	}
	var raw struct {
		ID           string `json:"Id"`
		OS           string `json:"Os"`
		Architecture string `json:"Architecture"`
		Size         int64  `json:"Size"`
		Config       *struct {
			Labels map[string]string `json:"Labels"`
			Env    []string          `json:"Env"`
		} `json:"Config"`
		RootFS *struct {
			Layers []string `json:"Layers"`
		} `json:"RootFS"`
	}
	if err := decodeOne(stdout, &raw); err != nil {
		return Image{}, false, fmt.Errorf("docker image inspect returned unreadable output: %w", err)
	}
	if !ValidImageID(raw.ID) {
		return Image{}, false, errors.New("docker image inspect returned an invalid image ID")
	}
	if raw.Size < 0 {
		return Image{}, false, errors.New("docker image inspect returned a negative image size")
	}
	image := Image{ID: raw.ID, OS: raw.OS, Architecture: raw.Architecture, Size: raw.Size, Labels: map[string]string{}}
	if raw.Config != nil {
		for k, v := range raw.Config.Labels {
			image.Labels[k] = v
		}
		image.Env = append([]string(nil), raw.Config.Env...)
	}
	if raw.RootFS != nil {
		image.Layers = append([]string(nil), raw.RootFS.Layers...)
	}
	return image, true, nil
}

// ServerInfo runs `info --format {{json .}}` (≤4 MiB of output). It fails when
// the daemon reported errors or no server version.
func ServerInfo(ctx context.Context, run Runner) (Info, error) {
	if run == nil {
		run = DefaultRunner
	}
	stdout, stderr, err := run(ctx, []string{"info", "--format", "{{json .}}"}, inspectLimit)
	if err != nil {
		return Info{}, commandError("docker info", err, stderr)
	}
	var raw struct {
		ServerVersion string   `json:"ServerVersion"`
		OSType        string   `json:"OSType"`
		Architecture  string   `json:"Architecture"`
		NCPU          int      `json:"NCPU"`
		MemTotal      int64    `json:"MemTotal"`
		ServerErrors  []string `json:"ServerErrors"`
	}
	if err := decodeOne(stdout, &raw); err != nil {
		return Info{}, fmt.Errorf("docker info returned unreadable output: %w", err)
	}
	if len(raw.ServerErrors) > 0 {
		return Info{}, fmt.Errorf("docker info reported a server error: %s", truncate(strings.Join(raw.ServerErrors, "; "), 512))
	}
	if raw.ServerVersion == "" {
		return Info{}, errors.New("docker info returned no server version")
	}
	if raw.NCPU < 0 || raw.MemTotal < 0 {
		return Info{}, errors.New("docker info returned negative resources")
	}
	return Info{ServerVersion: raw.ServerVersion, OSType: raw.OSType, Architecture: raw.Architecture, NCPU: raw.NCPU, MemTotal: raw.MemTotal}, nil
}

// decodeOne decodes exactly one JSON value followed only by whitespace.
func decodeOne(data []byte, v any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(v); err != nil {
		return err
	}
	if err := decoder.Decode(new(json.RawMessage)); err != io.EOF {
		return errors.New("more than one JSON value")
	}
	return nil
}

func commandError(what string, err error, stderr []byte) error {
	detail := strings.TrimSpace(string(stderr))
	if detail == "" {
		return fmt.Errorf("%s: %w", what, err)
	}
	return fmt.Errorf("%s: %w: %s", what, err, truncate(detail, 512))
}

func truncate(s string, limit int) string {
	if len(s) <= limit {
		return strings.ToValidUTF8(s, "�")
	}
	s = s[:limit]
	for len(s) > 0 && !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}
