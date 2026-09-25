// Package harness provides bounded repository tools and Docker-only execution.
// Repository code never runs directly on the host.
package harness

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/gvinsot/SwiftProof/app/internal/coverage"
	"github.com/gvinsot/SwiftProof/app/internal/model"
)

const maxFileBytes = 1024 * 1024

type Options struct {
	CandidateDir, BaseDir, ArtifactDir                string
	Commands                                          map[string][]string
	Image                                             string
	Diff                                              string
	Network                                           bool
	Timeout, MaxRuntime                               time.Duration
	MaxGeneratedTests, MaxOutputBytes, MemoryMB, CPUs int
}

type generatedTest struct {
	ID, Path, Content, Description string
	Reproduced                     bool
	GoTests                        []string
}

type execution struct {
	ExitCode int
	Err      error
	TimedOut bool
}
type executor func(context.Context, string, []string, io.Writer) execution

// captureExecutor keeps the container's standard output, which carries the
// framed coverage payload, on a separate host descriptor from its log.
type captureExecutor func(context.Context, string, []string, io.Writer, io.Writer) execution

type Harness struct {
	mu                    sync.Mutex
	opts                  Options
	root, candidate, base string
	runID                 string
	checks                []model.Check
	evidence              []model.Evidence
	artifacts             []model.Artifact
	audit                 []model.AuditEvent
	tests                 map[string]*generatedTest
	generated             int
	spent                 time.Duration
	closed                bool
	execute               executor
	executeCapture        captureExecutor
}

func New(opts Options) (*Harness, error) {
	if opts.CandidateDir == "" {
		return nil, errors.New("candidate snapshot is required")
	}
	if opts.Timeout == 0 {
		opts.Timeout = 60 * time.Second
	}
	if opts.MaxRuntime == 0 {
		opts.MaxRuntime = 10 * time.Minute
	}
	if opts.MaxOutputBytes == 0 {
		opts.MaxOutputBytes = 32 * 1024
	}
	if opts.MemoryMB == 0 {
		opts.MemoryMB = 1024
	}
	if opts.CPUs == 0 {
		opts.CPUs = 2
	}
	if opts.Timeout < 0 || opts.MaxRuntime < 0 || opts.MaxGeneratedTests < 0 || opts.MaxGeneratedTests > 100 || opts.MaxOutputBytes < 256 || opts.MaxOutputBytes > 4*1024*1024 || opts.MemoryMB < 64 || opts.MemoryMB > 65536 || opts.CPUs < 1 || opts.CPUs > 128 {
		return nil, errors.New("invalid harness resource limits")
	}
	if strings.ContainsAny(opts.Image, "\r\n\t ") || strings.HasPrefix(opts.Image, "-") {
		return nil, errors.New("invalid sandbox image")
	}
	commands := make(map[string][]string, len(opts.Commands))
	for k, v := range opts.Commands {
		if len(v) == 0 || strings.TrimSpace(v[0]) == "" {
			return nil, fmt.Errorf("empty %s command", k)
		}
		for _, arg := range v {
			if strings.ContainsRune(arg, 0) {
				return nil, errors.New("NUL byte in command")
			}
		}
		commands[k] = append([]string(nil), v...)
	}
	opts.Commands = commands
	root, err := os.MkdirTemp("", "swiftproof-harness-")
	if err != nil {
		return nil, err
	}
	h := &Harness{opts: opts, root: root, candidate: filepath.Join(root, "candidate"), runID: randomID(), tests: map[string]*generatedTest{}, execute: dockerExecute, executeCapture: dockerExecuteCapture}
	if err = copySnapshot(opts.CandidateDir, h.candidate); err != nil {
		os.RemoveAll(root)
		return nil, fmt.Errorf("candidate snapshot: %w", err)
	}
	if opts.BaseDir != "" {
		h.base = filepath.Join(root, "base")
		if err = copySnapshot(opts.BaseDir, h.base); err != nil {
			os.RemoveAll(root)
			return nil, fmt.Errorf("base snapshot: %w", err)
		}
	}
	if opts.ArtifactDir == "" {
		h.opts.ArtifactDir = filepath.Join(root, "artifacts")
	}
	if err = os.MkdirAll(h.opts.ArtifactDir, 0700); err != nil {
		os.RemoveAll(root)
		return nil, err
	}
	return h, nil
}

func (h *Harness) Close() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.closed = true
	return os.RemoveAll(h.root)
}
func (h *Harness) Checks() []model.Check {
	h.mu.Lock()
	defer h.mu.Unlock()
	checks := append([]model.Check(nil), h.checks...)
	for i := range checks {
		checks[i].Command = append([]string(nil), checks[i].Command...)
	}
	return checks
}
func (h *Harness) Evidence() []model.Evidence {
	h.mu.Lock()
	defer h.mu.Unlock()
	evidence := append([]model.Evidence(nil), h.evidence...)
	for i := range evidence {
		evidence[i].TestNames = append([]string(nil), evidence[i].TestNames...)
	}
	return evidence
}
func (h *Harness) Artifacts() []model.Artifact {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]model.Artifact(nil), h.artifacts...)
}
func (h *Harness) Audit() []model.AuditEvent {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]model.AuditEvent(nil), h.audit...)
}

func (h *Harness) Run(ctx context.Context, kind string) model.Check {
	h.mu.Lock()
	defer h.mu.Unlock()
	started := time.Now()
	c := h.run(ctx, kind, h.candidate, h.opts.Commands[kind])
	h.audit = append(h.audit, model.AuditEvent{Time: started.UTC(), Tool: "run_" + kind, Status: c.Status, DurationMS: time.Since(started).Milliseconds()})
	return c
}

func (h *Harness) run(ctx context.Context, kind, dir string, command []string) model.Check {
	c, _, _ := h.runWith(ctx, kind, dir, command, false)
	return c
}

// runWith executes one command. When withCoverage is set the container returns
// the coverage profile on its own bounded payload channel; the returned bytes
// are raw and unredacted so the profile can be parsed and hashed before any
// display transformation touches it.
func (h *Harness) runWith(ctx context.Context, kind, dir string, command []string, withCoverage bool) (model.Check, []byte, bool) {
	c := model.Check{ID: fmt.Sprintf("check-%d", len(h.checks)+1), Kind: kind, Command: append([]string(nil), command...), ExitCode: -1}
	started := time.Now()
	var payload *boundedWriter
	for i, arg := range c.Command {
		c.Command[i] = Redact(arg)
	}
	switch {
	case h.closed:
		c.Status, c.Output = "ERROR", "harness is closed"
	case len(command) == 0:
		c.Status, c.Output = "SKIPPED", "No command configured."
	case h.opts.Image == "":
		c.Status, c.Output = "SKIPPED", "No Docker image configured; repository code was not executed."
	case dir == "":
		c.Status, c.Output = "SKIPPED", "No baseline snapshot available."
	case h.spent >= h.opts.MaxRuntime:
		c.Status, c.Output = "SKIPPED", "Sandbox runtime budget exhausted."
	default:
		timeout := h.opts.Timeout
		if remaining := h.opts.MaxRuntime - h.spent; remaining < timeout {
			timeout = remaining
		}
		runCtx, cancel := context.WithTimeout(ctx, timeout)
		name := "swiftproof-" + randomID()
		out := &boundedWriter{limit: h.opts.MaxOutputBytes}
		var result execution
		if withCoverage {
			payload = &boundedWriter{limit: coverageLimit(h.opts.MaxOutputBytes)}
			result = h.executeCapture(runCtx, name, h.dockerArgsCoverage(name, dir, command), out, payload)
		} else {
			result = h.execute(runCtx, name, h.dockerArgs(name, dir, command), out)
		}
		cancel()
		c.ExitCode, c.Truncated, c.Output = result.ExitCode, out.truncated, Redact(string(out.data))
		switch {
		case result.TimedOut:
			c.Status = "TIMEOUT"
		case result.Err != nil:
			c.Status = "ERROR"
			c.Output += "\n" + Redact(result.Err.Error())
		case result.ExitCode == 0:
			c.Status = "PASS"
		case result.ExitCode >= 125:
			c.Status = "ERROR"
		case strings.HasPrefix(kind, "generated_test_") && generatedSetupFailure(c.Output):
			c.Status = "ERROR"
		case strings.Contains(c.Output, "fork/exec ") && (strings.Contains(c.Output, "permission denied") || strings.Contains(c.Output, "exec format error") || strings.Contains(c.Output, "no such file or directory")):
			c.Status = "ERROR"
		default:
			c.Status = "FAIL"
		}
		h.spent += time.Since(started)
	}
	c.DurationMS = time.Since(started).Milliseconds()
	c.Output = truncateUTF8(c.Output, h.opts.MaxOutputBytes)
	if c.Output != "" {
		if err := h.saveArtifact(c.ID+".log", "check_output", []byte(c.Output)); err != nil {
			c.Status = "ERROR"
			c.Output = truncateUTF8("Unable to retain check output: "+Redact(err.Error())+"\n"+c.Output, h.opts.MaxOutputBytes)
		}
	}
	h.checks = append(h.checks, c)
	if payload == nil {
		return c, nil, false
	}
	return c, payload.data, payload.truncated
}

// coverageLimit derives the payload budget from trusted policy rather than
// introducing an unconfigurable host buffer. A real profile runs to hundreds of
// kilobytes, far beyond a log budget.
func coverageLimit(maxOutputBytes int) int {
	limit := 16 * maxOutputBytes
	if limit < 256*1024 {
		limit = 256 * 1024
	}
	if limit > 4*1024*1024 {
		limit = 4 * 1024 * 1024
	}
	return limit
}

// RunCoverage executes the configured coverage command and returns the recorded
// check, the raw profile the container emitted, and the reason no measurement is
// available. A profile that cannot be retained as a hashed artifact is
// discarded: a coverage claim with no recorded evidence is unfalsifiable.
func (h *Harness) RunCoverage(ctx context.Context) (model.Check, []byte, string, string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	started := time.Now()
	command := append([]string(nil), h.opts.Commands[coverage.CommandKey]...)
	for i, arg := range command {
		command[i] = strings.ReplaceAll(arg, coverage.Placeholder, coverage.ProfilePath)
	}
	c, payload, truncated := h.runWith(ctx, coverage.CommandKey, h.candidate, command, true)
	h.audit = append(h.audit, model.AuditEvent{Time: started.UTC(), Tool: "run_" + coverage.CommandKey, Status: c.Status, DurationMS: time.Since(started).Milliseconds()})
	if c.Status != "PASS" && c.Status != "FAIL" {
		// Report the recorded status rather than paraphrase it: a TIMEOUT did run,
		// and an ERROR can mean the command ran but its log could not be retained.
		return c, nil, "", fmt.Sprintf("the coverage run did not complete (%s): %s", c.Status, truncateUTF8(strings.TrimSpace(c.Output), 200))
	}
	profile, err := coverage.DecodeFrame(payload, truncated)
	if err == nil {
		// Validate before labelling: an artifact recorded as a coverage profile
		// must be one, or the evidence record contradicts the report.
		_, err = coverage.ParseGoProfile(profile)
	}
	if err != nil {
		h.rejectPayload(c.ID, payload)
		return c, nil, "", err.Error()
	}
	if err := h.saveArtifact(c.ID+"-coverage.out", "coverage_profile", profile); err != nil {
		return c, nil, "", coverage.ErrArtifact.Error()
	}
	return c, profile, h.artifacts[len(h.artifacts)-1].SHA256, ""
}

// rejectPayload retains a bounded, redacted copy of what did arrive so a
// not-measured verdict stays auditable rather than merely asserted.
func (h *Harness) rejectPayload(checkID string, payload []byte) {
	if len(payload) == 0 {
		return
	}
	_ = h.saveArtifact(checkID+"-coverage-rejected.txt", "coverage_payload_rejected", []byte(truncateUTF8(Redact(string(payload)), 4096)))
}

// wrapperScript copies the sanitized read-only source into the ephemeral
// workspace and replaces itself with the configured command.
const wrapperScript = `cp -R /source/. /workspace/ && exec "$@"`

// coverageScript differs from wrapperScript in exactly one respect: it returns
// the profile the command wrote as a length-declared frame on the container's
// standard output, while the command's own output goes to standard error. It
// adds no mount, no volume, no writable host path and no surviving container.
// It is built from the frame constants so the producer and the decoder cannot
// drift apart.
var coverageScript = `cp -R /source/. /workspace/ 1>&2 || exit 125; "$@" >&2; s=$?; if [ -s ` + coverage.ProfilePath +
	` ]; then set -- $(wc -c < ` + coverage.ProfilePath + `); printf '` + coverage.FrameHeader + `%s\n' "$1"; cat ` +
	coverage.ProfilePath + `; printf '%s\n' '` + strings.TrimSuffix(coverage.FrameFooter, "\n") + `'; fi; exit $s`

func (h *Harness) dockerArgs(name, dir string, command []string) []string {
	return h.dockerArgsScript(name, dir, wrapperScript, command)
}

// dockerArgsCoverage keeps every isolation flag of dockerArgs; only the wrapper
// script differs. Both call one builder so a boundary flag can never be present
// on one path and missing on the other.
func (h *Harness) dockerArgsCoverage(name, dir string, command []string) []string {
	return h.dockerArgsScript(name, dir, coverageScript, command)
}

// No -i and no -t is ever passed: the docker CLI only keeps the container's
// standard output and standard error on separate host descriptors without a
// TTY, and the coverage payload channel depends on that separation.
func (h *Harness) dockerArgsScript(name, dir, script string, command []string) []string {
	network := "none"
	if h.opts.Network {
		network = "bridge"
	}
	args := []string{"run", "--rm", "--pull=never", "--name", name, "--network", network, "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--pids-limit=128", "--no-healthcheck", "--log-driver=none", "--ulimit=nofile=1024:1024", fmt.Sprintf("--memory=%dm", h.opts.MemoryMB), fmt.Sprintf("--memory-swap=%dm", h.opts.MemoryMB), fmt.Sprintf("--cpus=%d", h.opts.CPUs), "--user=65534:65534", "--tmpfs", fmt.Sprintf("/workspace:rw,exec,nosuid,nodev,mode=1777,size=%dm", h.opts.MemoryMB), "--tmpfs", fmt.Sprintf("/tmp:rw,exec,nosuid,nodev,mode=1777,size=%dm", h.opts.MemoryMB), "--mount", "type=bind,src=" + dir + ",dst=/source,readonly", "--workdir=/workspace", "--env=HOME=/tmp", "--env=TMPDIR=/tmp", "--env=GOCACHE=/tmp/go-build"}
	if !h.opts.Network {
		args = append(args, "--env=GOTOOLCHAIN=local", "--env=GOPROXY=off", "--env=GOSUMDB=off")
	}
	args = append(args, "--entrypoint=/bin/sh", h.opts.Image, "-c", script, "swiftproof")
	return append(args, command...)
}

func dockerExecute(ctx context.Context, name string, args []string, out io.Writer) execution {
	return runDocker(ctx, name, args, out, out)
}

// dockerExecuteCapture keeps the container's standard output, which carries the
// framed coverage payload, separate from its log.
func dockerExecuteCapture(ctx context.Context, name string, args []string, log, payload io.Writer) execution {
	return runDocker(ctx, name, args, payload, log)
}

func runDocker(ctx context.Context, name string, args []string, stdout, stderr io.Writer) execution {
	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Stdout, cmd.Stderr = stdout, stderr
	err := cmd.Run()
	// A killed docker client does not stop its container. Always issue bounded cleanup.
	cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cleanupOutput, cleanupErr := exec.CommandContext(cleanupCtx, "docker", "rm", "-f", name).CombinedOutput()
	if ctx.Err() != nil {
		if cleanupErr != nil && !strings.Contains(strings.ToLower(string(cleanupOutput)), "no such container") {
			return execution{ExitCode: -1, Err: fmt.Errorf("execution deadline or cancellation reached; Docker cleanup could not be confirmed: %w", cleanupErr)}
		}
		return execution{ExitCode: -1, Err: ctx.Err(), TimedOut: true}
	}
	if cleanupErr != nil && !strings.Contains(strings.ToLower(string(cleanupOutput)), "no such container") {
		return execution{ExitCode: -1, Err: fmt.Errorf("Docker cleanup could not be confirmed: %w", cleanupErr)}
	}
	if err == nil {
		return execution{ExitCode: 0}
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return execution{ExitCode: ee.ExitCode()}
	}
	return execution{ExitCode: -1, Err: err}
}

type boundedWriter struct {
	mu        sync.Mutex
	data      []byte
	limit     int
	truncated bool
}

func (w *boundedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	n := len(p)
	remaining := w.limit - len(w.data)
	if n > remaining {
		w.truncated = true
		p = p[:remaining]
	}
	w.data = append(w.data, p...)
	return n, nil
}

func randomID() string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}

func generatedSetupFailure(output string) bool {
	text := strings.ToLower(output)
	for _, marker := range []string{"[build failed]", "[setup failed]", "syntaxerror:", "importerror:", "modulenotfounderror:", "cannot find module", "err_module_not_found", "error: cannot find", "command not found", "permission denied", "no required module provides package"} {
		if strings.Contains(text, marker) {
			return true
		}
	}
	return false
}

func truncateUTF8(s string, limit int) string {
	if len(s) <= limit {
		return strings.ToValidUTF8(s, "�")
	}
	s = s[:limit]
	for len(s) > 0 && !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}

var redactRules = []*regexp.Regexp{
	regexp.MustCompile(`(?is)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)`),
	regexp.MustCompile(`(?i)(?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|secret|password|passwd|authorization)["']?\s*[=:]\s*["']?[^\s,"'}]+`),
	regexp.MustCompile(`(?i)Bearer\s+[A-Za-z0-9._~+/=-]+`),
	regexp.MustCompile(`(?:sk-[A-Za-z0-9_-]{8,}|gh[pousr]_[A-Za-z0-9_]{8,}|github_pat_[A-Za-z0-9_]{8,}|AKIA[A-Z0-9]{16})`),
	regexp.MustCompile(`eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`),
	regexp.MustCompile(`://[^\s/@:]+:[^\s/@]+@`),
}

// Redact masks common credential formats before any tool output or report is emitted.
// It is defense in depth; snapshots also exclude known secret-bearing paths.
func Redact(s string) string {
	for _, re := range redactRules {
		s = re.ReplaceAllStringFunc(s, func(match string) string { return "[REDACTED]" + strings.Repeat("\n", strings.Count(match, "\n")) })
	}
	return s
}

// IsSensitivePath identifies secret-bearing names excluded from tools and snapshots.
func IsSensitivePath(path string) bool { return sensitivePath(path) }

func sensitivePath(path string) bool {
	for _, part := range strings.Split(strings.ToLower(filepath.ToSlash(path)), "/") {
		if strings.HasPrefix(part, ".env") || strings.HasSuffix(part, ".pem") || strings.HasSuffix(part, ".p12") || strings.HasSuffix(part, ".pfx") || strings.HasSuffix(part, ".key") {
			return true
		}
		switch part {
		case ".git", ".ssh", ".aws", ".kube", ".docker", ".gnupg", ".netrc", ".npmrc", ".pypirc", "credentials", "credentials.json", "secrets.json", "secrets.yaml", "secrets.yml", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519":
			return true
		}
	}
	return false
}

func safePath(root, rel string) (string, error) {
	if rel == "" || strings.HasPrefix(rel, "/") || strings.ContainsRune(rel, 0) || strings.ContainsAny(rel, "\\:") || filepath.IsAbs(rel) || sensitivePath(rel) {
		return "", errors.New("path is invalid or sensitive")
	}
	clean := filepath.Clean(filepath.FromSlash(rel))
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", errors.New("path escapes snapshot")
	}
	path := filepath.Join(root, clean)
	// Reject symlinks at every component, including links to locations inside the tree.
	cursor := root
	for _, part := range strings.Split(clean, string(filepath.Separator)) {
		cursor = filepath.Join(cursor, part)
		info, err := os.Lstat(cursor)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return "", err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return "", errors.New("symlink paths are not allowed")
		}
	}
	return path, nil
}

func copySnapshot(src, dst string) error {
	root, err := filepath.Abs(src)
	if err != nil {
		return err
	}
	info, err := os.Lstat(root)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("snapshot must be a real directory")
	}
	var total int64
	files := 0
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if rel != "." && (sensitivePath(rel) || d.Type()&os.ModeSymlink != 0) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0755)
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		files++
		total += info.Size()
		if files > 100000 || info.Size() > 32*1024*1024 || total > 512*1024*1024 {
			return errors.New("snapshot exceeds safe copy limits (100,000 files, 32 MiB/file, 512 MiB total)")
		}
		in, err := os.Open(path)
		if err != nil {
			return err
		}
		defer in.Close()
		mode := fs.FileMode(0644)
		if info.Mode()&0111 != 0 {
			mode = 0755
		}
		out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
		if err != nil {
			return err
		}
		_, err = io.Copy(out, io.LimitReader(in, 32*1024*1024+1))
		closeErr := out.Close()
		if err != nil {
			return err
		}
		return closeErr
	})
}

func (h *Harness) saveArtifact(name, kind string, data []byte) error {
	path := filepath.Join(h.opts.ArtifactDir, h.runID+"-"+name)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	sum := sha256.Sum256(data)
	h.artifacts = append(h.artifacts, model.Artifact{Path: path, Kind: kind, SHA256: hex.EncodeToString(sum[:])})
	return nil
}

// Call accepts only the published tools; arbitrary commands and environment variables
// are never accepted from a reviewer. All calls, including rejected calls, are audited.
func (h *Harness) Call(ctx context.Context, tool string, args json.RawMessage) (out json.RawMessage, err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	started := time.Now()
	defer func() {
		status := "OK"
		if err != nil {
			status = "ERROR"
		}
		auditArgs := string(args)
		if tool == "create_test" {
			var a map[string]any
			if json.Unmarshal(args, &a) == nil {
				delete(a, "content")
				b, _ := json.Marshal(a)
				auditArgs = string(b)
			}
		}
		h.audit = append(h.audit, model.AuditEvent{Time: started.UTC(), Tool: tool, Arguments: truncateUTF8(Redact(auditArgs), 4096), Status: status, DurationMS: time.Since(started).Milliseconds()})
	}()
	if h.closed {
		return nil, errors.New("harness is closed")
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	if len(args) > 2*maxFileBytes {
		return nil, errors.New("tool arguments exceed size limit")
	}
	var a struct {
		Path        string `json:"path"`
		Start       int    `json:"start"`
		End         int    `json:"end"`
		Query       string `json:"query"`
		Symbol      string `json:"symbol"`
		Content     string `json:"content"`
		Description string `json:"description"`
		TestID      string `json:"test_id"`
	}
	if len(args) == 0 {
		args = []byte("{}")
	}
	decoder := json.NewDecoder(strings.NewReader(string(args)))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&a); err != nil {
		return nil, err
	}
	if decoder.Decode(new(any)) != io.EOF {
		return nil, errors.New("tool arguments must contain one JSON object")
	}
	var value any
	switch tool {
	case "read_file":
		value, err = h.readFile(a.Path, a.Start, a.End)
		if err == nil {
			observation := value.(map[string]any)
			e := model.Evidence{ID: fmt.Sprintf("evidence-%d", len(h.evidence)+1), Kind: "source_observation", Description: fmt.Sprintf("Candidate source lines %v-%v", observation["start"], observation["end"]), Path: a.Path, Output: observation["content"].(string), Status: "OBSERVED"}
			h.evidence = append(h.evidence, e)
			observation["evidence_id"] = e.ID
		}
	case "get_diff":
		diff := SanitizeDiff(h.opts.Diff)
		if a.Path != "" {
			if _, err = safePath(h.candidate, a.Path); err != nil {
				break
			}
			var change model.Change
			if json.Unmarshal([]byte(diff), &change) == nil {
				files := make([]model.ChangedFile, 0)
				for _, file := range change.Files {
					if file.Path == a.Path || file.OldPath == a.Path {
						files = append(files, file)
					}
				}
				change.Files = files
				b, _ := json.Marshal(change)
				diff = string(b)
			} else {
				diff = filterDiff(diff, a.Path)
			}
		}
		value = map[string]any{"diff": truncateUTF8(diff, h.opts.MaxOutputBytes), "truncated": len(diff) > h.opts.MaxOutputBytes}
	case "search_code":
		value, err = h.search(ctx, a.Query, false)
	case "find_references", "inspect_symbol":
		value, err = h.search(ctx, a.Symbol, true)
	case "run_tests":
		value = h.run(ctx, "test", h.candidate, h.opts.Commands["test"])
	case "run_test":
		if !isTestPath(a.Path) {
			err = errors.New("path must identify an existing test file")
			break
		}
		var path string
		path, err = safePath(h.candidate, a.Path)
		if err != nil {
			break
		}
		var content []byte
		content, err = readBounded(path)
		if err != nil {
			break
		}
		command := h.testCommand(a.Path)
		if strings.HasSuffix(a.Path, "_test.go") && len(command) > 1 && filepath.Base(command[0]) == "go" && command[1] == "test" {
			var names []string
			names, err = generatedGoTests(a.Path, string(content))
			if err != nil {
				break
			}
			command = selectGoTests(command, names)
		}
		value = h.run(ctx, "existing_test", h.candidate, command)
	case "run_typecheck":
		value = h.run(ctx, "typecheck", h.candidate, h.opts.Commands["typecheck"])
	case "run_build":
		value = h.run(ctx, "build", h.candidate, h.opts.Commands["build"])
	case "create_test":
		value, err = h.createTest(a.Path, a.Content, a.Description)
	case "run_generated_test":
		value, err = h.runGenerated(ctx, a.TestID)
	case "delete_generated_test":
		t, ok := h.tests[a.TestID]
		if !ok {
			err = errors.New("unknown generated test")
		} else if t.Reproduced {
			err = errors.New("reproducing tests are retained as evidence")
		} else {
			delete(h.tests, a.TestID)
			value = map[string]any{"deleted": a.TestID}
		}
	default:
		err = fmt.Errorf("unknown tool: %s", tool)
	}
	if err != nil {
		return nil, err
	}
	return json.Marshal(value)
}

func (h *Harness) readFile(rel string, start, end int) (any, error) {
	path, err := safePath(h.candidate, rel)
	if err != nil {
		return nil, err
	}
	b, err := readBounded(path)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(Redact(string(b)), "\n")
	if start == 0 {
		start = 1
	}
	if end == 0 {
		end = start + 199
	}
	if start < 1 || end < start || end-start > 1999 {
		return nil, errors.New("invalid line range (maximum 2,000 lines)")
	}
	if start > len(lines) {
		return nil, errors.New("start line is past end of file")
	}
	if end > len(lines) {
		end = len(lines)
	}
	content := strings.Join(lines[start-1:end], "\n")
	return map[string]any{"path": rel, "start": start, "end": end, "content": truncateUTF8(content, h.opts.MaxOutputBytes), "truncated": len(content) > h.opts.MaxOutputBytes}, nil
}

func readBounded(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	b, err := io.ReadAll(io.LimitReader(f, maxFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxFileBytes {
		return nil, errors.New("file exceeds 1 MiB read limit")
	}
	if !utf8.Valid(b) || strings.ContainsRune(string(b), 0) {
		return nil, errors.New("binary file cannot be read")
	}
	return b, nil
}

func (h *Harness) search(ctx context.Context, query string, symbol bool) (any, error) {
	if query == "" || len(query) > 256 {
		return nil, errors.New("search query must contain 1 to 256 bytes")
	}
	var re *regexp.Regexp
	if symbol {
		re = regexp.MustCompile(`\b` + regexp.QuoteMeta(query) + `\b`)
	}
	type match struct {
		Path    string `json:"path"`
		Line    int    `json:"line"`
		Content string `json:"content"`
	}
	matches := []match{}
	truncated := false
	bytesUsed := 0
	count := 0
	err := filepath.WalkDir(h.candidate, func(path string, d fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		rel, e := filepath.Rel(h.candidate, path)
		if e != nil {
			return e
		}
		if sensitivePath(rel) || d.Type()&os.ModeSymlink != 0 {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			return nil
		}
		count++
		if count > 20000 {
			truncated = true
			return fs.SkipAll
		}
		b, e := readBounded(path)
		if e != nil {
			return nil
		}
		for i, line := range strings.Split(Redact(string(b)), "\n") {
			found := strings.Contains(line, query)
			if re != nil {
				found = re.MatchString(line)
			}
			if !found {
				continue
			}
			line = truncateUTF8(line, 1000)
			if len(matches) >= 100 || bytesUsed+len(line) > h.opts.MaxOutputBytes {
				truncated = true
				return fs.SkipAll
			}
			bytesUsed += len(line)
			matches = append(matches, match{filepath.ToSlash(rel), i + 1, line})
		}
		return nil
	})
	return map[string]any{"matches": matches, "truncated": truncated, "method": "lexical (not semantic symbol resolution)"}, err
}

func filterDiff(diff, path string) string {
	var out strings.Builder
	keep := false
	for _, line := range strings.Split(diff, "\n") {
		if strings.HasPrefix(line, "diff --git ") {
			keep = strings.HasSuffix(line, " b/"+path) || strings.Contains(line, " a/"+path+" b/")
		}
		if keep {
			out.WriteString(line)
			out.WriteByte('\n')
		}
	}
	return out.String()
}

// SanitizeDiff excludes secret-bearing file patches and redacts credential literals.
func SanitizeDiff(diff string) string {
	var change model.Change
	if json.Unmarshal([]byte(diff), &change) == nil {
		for i := range change.Files {
			file := &change.Files[i]
			if IsSensitivePath(file.Path) || IsSensitivePath(file.OldPath) {
				file.Hunks = nil
				continue
			}
			for j := range file.Hunks {
				for k := range file.Hunks[j].Lines {
					file.Hunks[j].Lines[k].Content = Redact(file.Hunks[j].Lines[k].Content)
				}
			}
		}
		b, _ := json.Marshal(change)
		return string(b)
	}
	var out strings.Builder
	keep := true
	for _, line := range strings.Split(diff, "\n") {
		if strings.HasPrefix(line, "diff --git ") {
			keep = true
			for _, part := range strings.Fields(strings.TrimPrefix(line, "diff --git ")) {
				part = strings.Trim(part, "\"")
				if len(part) > 2 {
					part = part[2:]
				}
				if sensitivePath(part) {
					keep = false
				}
			}
		}
		if keep {
			out.WriteString(line)
			out.WriteByte('\n')
		}
	}
	return Redact(out.String())
}

func isTestPath(path string) bool {
	b := strings.ToLower(filepath.Base(path))
	return strings.HasSuffix(b, "_test.go") || strings.HasSuffix(b, ".test.ts") || strings.HasSuffix(b, ".test.tsx") || strings.HasSuffix(b, ".spec.ts") || strings.HasSuffix(b, ".spec.tsx") || strings.HasSuffix(b, ".test.js") || strings.HasSuffix(b, ".spec.js") || strings.HasPrefix(b, "test_") && strings.HasSuffix(b, ".py") || strings.HasSuffix(b, "_test.py")
}

func (h *Harness) createTest(path, content, description string) (any, error) {
	if h.generated >= h.opts.MaxGeneratedTests {
		return nil, errors.New("generated test budget exhausted")
	}
	if !isTestPath(path) {
		return nil, errors.New("generated file must use a supported test filename")
	}
	if len(content) == 0 || len(content) > maxFileBytes || strings.ContainsRune(content, 0) {
		return nil, errors.New("generated test content must contain 1 byte to 1 MiB of text")
	}
	for _, root := range []string{h.candidate, h.base} {
		if root == "" {
			continue
		}
		p, err := safePath(root, path)
		if err != nil {
			return nil, err
		}
		if _, err = os.Lstat(p); !os.IsNotExist(err) {
			return nil, errors.New("generated test cannot overwrite an existing snapshot path")
		}
	}
	for _, test := range h.tests {
		if test.Path == path {
			return nil, errors.New("generated test path is already reserved")
		}
	}
	path = filepath.ToSlash(filepath.Clean(filepath.FromSlash(path)))
	var goTests []string
	if strings.HasSuffix(path, "_test.go") {
		var err error
		goTests, err = generatedGoTests(path, content)
		if err != nil {
			return nil, err
		}
		for _, root := range []string{h.base, h.candidate} {
			if err = rejectGoTestCollisions(root, path, goTests); err != nil {
				return nil, err
			}
		}
	}
	h.generated++
	id := fmt.Sprintf("generated-test-%d", h.generated)
	t := &generatedTest{ID: id, Path: path, Content: content, Description: Redact(description), GoTests: goTests}
	h.tests[id] = t
	return map[string]any{"test_id": id, "path": path}, nil
}

func (h *Harness) runGenerated(ctx context.Context, id string) (any, error) {
	t, ok := h.tests[id]
	if !ok {
		return nil, errors.New("unknown generated test")
	}
	command := h.testCommand(t.Path)
	hasFile := len(command) > 0
	goRunner := len(t.GoTests) > 0 && len(command) > 0 && verifiableGoTemplate(h.opts.Commands["generated_test"])
	if goRunner {
		command = selectGoTests(command, t.GoTests)
	}
	cleanup := []string{}
	createdDirs := []string{}
	defer func() {
		for _, path := range cleanup {
			_ = os.Remove(path)
		}
		for i := len(createdDirs) - 1; i >= 0; i-- {
			_ = os.Remove(createdDirs[i])
		}
	}()
	for _, root := range []string{h.base, h.candidate} {
		if root == "" {
			continue
		}
		path, err := safePath(root, t.Path)
		if err != nil {
			return nil, err
		}
		var missing []string
		for dir := filepath.Dir(path); dir != root; dir = filepath.Dir(dir) {
			if _, e := os.Lstat(dir); e == nil {
				break
			} else if !os.IsNotExist(e) {
				return nil, e
			}
			missing = append(missing, dir)
		}
		if err = os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			return nil, err
		}
		for i := len(missing) - 1; i >= 0; i-- {
			createdDirs = append(createdDirs, missing[i])
		}
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
		if err != nil {
			return nil, err
		}
		cleanup = append(cleanup, path)
		_, writeErr := f.WriteString(t.Content)
		closeErr := f.Close()
		if writeErr != nil {
			return nil, writeErr
		}
		if closeErr != nil {
			return nil, closeErr
		}
	}
	base := h.run(ctx, "generated_test_base", h.base, command)
	candidate := h.run(ctx, "generated_test_candidate", h.candidate, command)
	if goRunner {
		base = ValidateGoExecution(base, t.GoTests)
		candidate = ValidateGoExecution(candidate, t.GoTests)
		h.checks[len(h.checks)-2] = base
		h.checks[len(h.checks)-1] = candidate
	}
	status := "UNVERIFIED"
	if goRunner && base.Status == "PASS" && candidate.Status == "FAIL" {
		status = "REPRODUCED"
	}
	if goRunner && base.Status == "PASS" && candidate.Status == "PASS" {
		status = "NOT_REPRODUCED"
	}
	if status == "REPRODUCED" && !t.Reproduced {
		if err := h.saveArtifact(t.ID+"-"+filepath.Base(t.Path), "generated_test", []byte(t.Content)); err != nil {
			return nil, fmt.Errorf("persist reproducer: %w", err)
		}
		t.Reproduced = true
	}
	e := model.Evidence{ID: fmt.Sprintf("evidence-%d", len(h.evidence)+1), Kind: "differential_test", Description: t.Description, Path: t.Path, CheckID: candidate.ID, BaseCheckID: base.ID, Status: status}
	if goRunner {
		e.Runner = "go_test_json"
		e.TestNames = append([]string(nil), t.GoTests...)
	}
	if !hasFile {
		e.Description += " (generated_test command with {file} or {package} is not configured)"
	} else if !goRunner {
		e.Description += " (runner has no supported named-test execution verifier; outcome is inconclusive)"
	}
	if goRunner && status == "UNVERIFIED" {
		e.Description += " (the generated named test must execute on both revisions; setup failures, skips, truncated output, and unrelated suite failures are inconclusive)"
	}
	h.evidence = append(h.evidence, e)
	return map[string]any{"evidence": e, "base_check": base, "candidate_check": candidate}, nil
}

func (h *Harness) testCommand(path string) []string {
	command := append([]string(nil), h.opts.Commands["generated_test"]...)
	hasFile := false
	for i, arg := range command {
		if strings.Contains(arg, "{file}") {
			hasFile = true
			arg = strings.ReplaceAll(arg, "{file}", path)
		}
		if strings.Contains(arg, "{package}") {
			hasFile = true
			pkg := filepath.ToSlash(filepath.Dir(path))
			if pkg != "." {
				pkg = "./" + pkg
			}
			arg = strings.ReplaceAll(arg, "{package}", pkg)
		}
		command[i] = arg
	}
	if !hasFile {
		return nil
	}
	return command
}

// ToolDefinitions returns the provider-independent function schema used by reviewers.
func ToolDefinitions() []map[string]any {
	type tool struct {
		name, description string
		properties        map[string]any
		required          []string
	}
	str := func(description string) any { return map[string]any{"type": "string", "description": description} }
	tools := []tool{
		{"read_file", "Read a bounded, redacted candidate file; paths are repository-relative.", map[string]any{"path": str("File path"), "start": map[string]any{"type": "integer", "minimum": 1}, "end": map[string]any{"type": "integer", "minimum": 1}}, []string{"path"}},
		{"get_diff", "Read the change diff, optionally for one path.", map[string]any{"path": str("Optional file path")}, nil},
		{"search_code", "Search a literal string in candidate source files.", map[string]any{"query": str("Literal query")}, []string{"query"}},
		{"find_references", "Find lexical symbol occurrences; not semantic reference resolution.", map[string]any{"symbol": str("Symbol")}, []string{"symbol"}},
		{"inspect_symbol", "Inspect lexical symbol occurrences; not semantic resolution.", map[string]any{"symbol": str("Symbol")}, []string{"symbol"}},
		{"run_tests", "Run the configured existing test command in an isolated container.", map[string]any{}, nil},
		{"run_test", "Run an existing test file using the configured test template; Go execution selects its named tests.", map[string]any{"path": str("Existing test file path")}, []string{"path"}},
		{"run_typecheck", "Run the configured typecheck command in an isolated container.", map[string]any{}, nil},
		{"run_build", "Run the configured build command in an isolated container.", map[string]any{}, nil},
		{"create_test", "Create an adversarial test in an ephemeral snapshot; never overwrites source. Go files must define uniquely named TestX(t *testing.T) functions.", map[string]any{"path": str("New test path, e.g. pkg/swiftproof_regression_test.go"), "content": str("Exact test source"), "description": str("What behavior the test checks")}, []string{"path", "content"}},
		{"run_generated_test", "Run identical generated tests on base and candidate. Verified Go named-test events support differential conclusions; other runners remain UNVERIFIED.", map[string]any{"test_id": str("ID returned by create_test")}, []string{"test_id"}},
		{"delete_generated_test", "Discard a generated test that has not reproduced an issue.", map[string]any{"test_id": str("Generated test ID")}, []string{"test_id"}},
	}
	result := make([]map[string]any, 0, len(tools))
	for _, t := range tools {
		sort.Strings(t.required)
		required := t.required
		if required == nil {
			required = []string{}
		}
		result = append(result, map[string]any{"type": "function", "function": map[string]any{"name": t.name, "description": t.description, "parameters": map[string]any{"type": "object", "properties": t.properties, "required": required, "additionalProperties": false}}})
	}
	return result
}
