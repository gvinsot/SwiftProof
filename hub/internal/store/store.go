// Package store persists hub state as JSON files under one data directory.
//
// The hub tracks a few hundred repositories per user and a bounded history of
// reports; a directory of atomically replaced files keeps the deployment free
// of any database dependency, which matters for an on-premise install. Keys
// are derived, never taken from user input, and every path is validated before
// it reaches the filesystem.
package store

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gvinsot/SwiftProof/hub/internal/report"
)

// ErrNotFound is returned when a record does not exist.
var ErrNotFound = errors.New("not found")

// MaxHistory bounds how many reports are kept per repository.
const MaxHistory = 50

// maxRecordBytes bounds a stored report; the CLI truncates its own outputs, so
// a larger file means something is wrong and must not be loaded into memory.
const maxRecordBytes = 32 << 20

// Run states.
const (
	StatusQueued  = "queued"
	StatusRunning = "running"
	StatusDone    = "done"
	StatusFailed  = "failed"
)

// User is an authenticated forge account. Tokens are stored sealed.
type User struct {
	Key          string    `json:"key"`
	Provider     string    `json:"provider"`
	ID           string    `json:"id"`
	Login        string    `json:"login"`
	Name         string    `json:"name,omitempty"`
	AvatarURL    string    `json:"avatar_url,omitempty"`
	WebURL       string    `json:"web_url,omitempty"`
	Token        string    `json:"token"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	TokenExpiry  time.Time `json:"token_expiry,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// Run is the state of one analysis, kept both on the repository (as the latest
// run) and in the report history.
type Run struct {
	Commit      string         `json:"commit"`
	BaseCommit  string         `json:"base_commit,omitempty"`
	Ref         string         `json:"ref,omitempty"`
	Message     string         `json:"message,omitempty"`
	Author      string         `json:"author,omitempty"`
	Status      string         `json:"status"`
	Error       string         `json:"error,omitempty"`
	Trigger     string         `json:"trigger,omitempty"`
	QueuedAt    time.Time      `json:"queued_at"`
	StartedAt   time.Time      `json:"started_at,omitempty"`
	FinishedAt  time.Time      `json:"finished_at,omitempty"`
	DurationMS  int64          `json:"duration_ms,omitempty"`
	Summary     report.Summary `json:"summary"`
	ToolVersion string         `json:"tool_version,omitempty"`
}

// Repo is one tracked repository of one user.
type Repo struct {
	Key           string    `json:"key"`
	Provider      string    `json:"provider"`
	ID            string    `json:"id"`
	FullName      string    `json:"full_name"`
	WebURL        string    `json:"web_url,omitempty"`
	CloneURL      string    `json:"clone_url,omitempty"`
	DefaultBranch string    `json:"default_branch"`
	Private       bool      `json:"private"`
	Admin         bool      `json:"admin"`
	HasPolicy     bool      `json:"has_policy"`
	PolicyAt      time.Time `json:"policy_at,omitempty"`
	Monitored     bool      `json:"monitored"`
	HookID        string    `json:"hook_id,omitempty"`
	HookKey       string    `json:"hook_key,omitempty"`
	HookSecret    string    `json:"hook_secret,omitempty"`
	Latest        *Run      `json:"latest,omitempty"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// PublicRepo is the repository projection sent to a browser. It deliberately
// omits the webhook secret and the routing key, which are credentials.
type PublicRepo struct {
	Key           string    `json:"key"`
	Provider      string    `json:"provider"`
	FullName      string    `json:"full_name"`
	WebURL        string    `json:"web_url,omitempty"`
	DefaultBranch string    `json:"default_branch"`
	Private       bool      `json:"private"`
	Admin         bool      `json:"admin"`
	HasPolicy     bool      `json:"has_policy"`
	Monitored     bool      `json:"monitored"`
	Latest        *Run      `json:"latest,omitempty"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// Public projects a repository for the API.
func (r *Repo) Public() PublicRepo {
	return PublicRepo{
		Key: r.Key, Provider: r.Provider, FullName: r.FullName, WebURL: r.WebURL,
		DefaultBranch: r.DefaultBranch, Private: r.Private, Admin: r.Admin,
		HasPolicy: r.HasPolicy, Monitored: r.Monitored, Latest: r.Latest, UpdatedAt: r.UpdatedAt,
	}
}

// Record is a stored report: its run metadata plus the raw confidence report.
type Record struct {
	Run
	UserKey  string          `json:"user_key"`
	RepoKey  string          `json:"repo_key"`
	RepoName string          `json:"repo_name"`
	Raw      json.RawMessage `json:"raw,omitempty"`
}

// HookRoute maps a webhook routing key onto the repository it belongs to.
type HookRoute struct {
	UserKey  string `json:"user_key"`
	RepoKey  string `json:"repo_key"`
	Provider string `json:"provider"`
}

// Store is a concurrency-safe directory of JSON records.
type Store struct {
	dir string
	mu  sync.RWMutex
}

// Open prepares the data directory.
func Open(dir string) (*Store, error) {
	for _, sub := range []string{"users", "repos", "reports", "hooks"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o700); err != nil {
			return nil, fmt.Errorf("data directory: %w", err)
		}
	}
	return &Store{dir: dir}, nil
}

var keyPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,120}$`)

// Key derives a filesystem-safe, collision-free key from an identity. The
// readable prefix helps an operator inspect the data directory; the digest
// suffix keeps distinct identities distinct.
func Key(parts ...string) string {
	raw := strings.Join(parts, "/")
	sum := sha256.Sum256([]byte(raw))
	var b strings.Builder
	for _, r := range raw {
		if len(b.String()) >= 48 {
			break
		}
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	return b.String() + "-" + hex.EncodeToString(sum[:6])
}

// ValidKey reports whether a key received from a request is safe to use as a
// path element. Anything else is rejected before touching the filesystem.
func ValidKey(key string) bool {
	return keyPattern.MatchString(key) && !strings.Contains(key, "..")
}

func (s *Store) path(parts ...string) (string, error) {
	for _, p := range parts[:len(parts)-1] {
		if !ValidKey(p) {
			return "", fmt.Errorf("invalid key %q", p)
		}
	}
	last := parts[len(parts)-1]
	if !ValidKey(strings.TrimSuffix(last, ".json")) {
		return "", fmt.Errorf("invalid key %q", last)
	}
	return filepath.Join(append([]string{s.dir}, parts...)...), nil
}

func writeJSON(path string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	// Replace atomically: a crash mid-write must not leave a half record.
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func readJSON(path string, value any) error {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return ErrNotFound
		}
		return err
	}
	if info.Size() > maxRecordBytes {
		return fmt.Errorf("record %s exceeds %d bytes", filepath.Base(path), maxRecordBytes)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return ErrNotFound
		}
		return err
	}
	return json.Unmarshal(data, value)
}

// PutUser stores or refreshes an account.
func (s *Store) PutUser(u *User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	path, err := s.path("users", u.Key+".json")
	if err != nil {
		return err
	}
	u.UpdatedAt = time.Now().UTC()
	if u.CreatedAt.IsZero() {
		u.CreatedAt = u.UpdatedAt
	}
	return writeJSON(path, u)
}

// User loads an account.
func (s *Store) User(key string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	path, err := s.path("users", key+".json")
	if err != nil {
		return nil, err
	}
	var u User
	if err := readJSON(path, &u); err != nil {
		return nil, err
	}
	return &u, nil
}

// PutRepo stores a repository of a user.
func (s *Store) PutRepo(userKey string, r *Repo) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.putRepoLocked(userKey, r)
}

func (s *Store) putRepoLocked(userKey string, r *Repo) error {
	path, err := s.path("repos", userKey, r.Key+".json")
	if err != nil {
		return err
	}
	r.UpdatedAt = time.Now().UTC()
	return writeJSON(path, r)
}

// Repo loads one repository.
func (s *Store) Repo(userKey, repoKey string) (*Repo, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.repoLocked(userKey, repoKey)
}

func (s *Store) repoLocked(userKey, repoKey string) (*Repo, error) {
	path, err := s.path("repos", userKey, repoKey+".json")
	if err != nil {
		return nil, err
	}
	var r Repo
	if err := readJSON(path, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// UpdateRepo applies mutate to a stored repository under the store lock, so
// that concurrent webhook deliveries cannot lose an update.
func (s *Store) UpdateRepo(userKey, repoKey string, mutate func(*Repo) error) (*Repo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, err := s.repoLocked(userKey, repoKey)
	if err != nil {
		return nil, err
	}
	if err := mutate(r); err != nil {
		return nil, err
	}
	if err := s.putRepoLocked(userKey, r); err != nil {
		return nil, err
	}
	return r, nil
}

// Repos lists the repositories of a user, most recently updated first.
func (s *Store) Repos(userKey string) ([]*Repo, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !ValidKey(userKey) {
		return nil, fmt.Errorf("invalid key %q", userKey)
	}
	dir := filepath.Join(s.dir, "repos", userKey)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	repos := make([]*Repo, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		var r Repo
		if err := readJSON(filepath.Join(dir, e.Name()), &r); err != nil {
			continue
		}
		repos = append(repos, &r)
	}
	sort.Slice(repos, func(i, j int) bool { return repos[i].FullName < repos[j].FullName })
	return repos, nil
}

// PutHook registers the routing key of a repository webhook.
func (s *Store) PutHook(hookKey string, route HookRoute) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	path, err := s.path("hooks", hookKey+".json")
	if err != nil {
		return err
	}
	return writeJSON(path, route)
}

// Hook resolves a webhook routing key.
func (s *Store) Hook(hookKey string) (HookRoute, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	path, err := s.path("hooks", hookKey+".json")
	if err != nil {
		return HookRoute{}, err
	}
	var route HookRoute
	if err := readJSON(path, &route); err != nil {
		return HookRoute{}, err
	}
	return route, nil
}

// DeleteHook forgets a webhook routing key.
func (s *Store) DeleteHook(hookKey string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	path, err := s.path("hooks", hookKey+".json")
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// PutRecord stores a report and trims the history to MaxHistory entries.
func (s *Store) PutRecord(rec *Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !ValidKey(rec.Commit) {
		return fmt.Errorf("invalid commit %q", rec.Commit)
	}
	path, err := s.path("reports", rec.UserKey, rec.RepoKey, rec.Commit+".json")
	if err != nil {
		return err
	}
	if err := writeJSON(path, rec); err != nil {
		return err
	}
	return s.trimLocked(filepath.Dir(path))
}

// trimLocked keeps the most recent MaxHistory reports of one repository.
func (s *Store) trimLocked(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	type aged struct {
		name string
		mod  time.Time
	}
	files := make([]aged, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		files = append(files, aged{e.Name(), info.ModTime()})
	}
	if len(files) <= MaxHistory {
		return nil
	}
	sort.Slice(files, func(i, j int) bool { return files[i].mod.After(files[j].mod) })
	for _, f := range files[MaxHistory:] {
		os.Remove(filepath.Join(dir, f.name))
	}
	return nil
}

// Record loads one stored report.
func (s *Store) Record(userKey, repoKey, commit string) (*Record, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	path, err := s.path("reports", userKey, repoKey, commit+".json")
	if err != nil {
		return nil, err
	}
	var rec Record
	if err := readJSON(path, &rec); err != nil {
		return nil, err
	}
	return &rec, nil
}

// History lists the stored runs of a repository, newest first, without their
// raw reports.
func (s *Store) History(userKey, repoKey string, limit int) ([]Run, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !ValidKey(userKey) || !ValidKey(repoKey) {
		return nil, fmt.Errorf("invalid key")
	}
	dir := filepath.Join(s.dir, "reports", userKey, repoKey)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	runs := make([]Run, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		var rec Record
		if err := readJSON(filepath.Join(dir, e.Name()), &rec); err != nil {
			continue
		}
		rec.Raw = nil
		runs = append(runs, rec.Run)
	}
	sort.Slice(runs, func(i, j int) bool { return runs[i].QueuedAt.After(runs[j].QueuedAt) })
	if limit > 0 && len(runs) > limit {
		runs = runs[:limit]
	}
	return runs, nil
}
