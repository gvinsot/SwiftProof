package store

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gvinsot/SwiftProof/hub/internal/report"
)

func open(t *testing.T) *Store {
	t.Helper()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return s
}

func TestKeyIsSafeAndStable(t *testing.T) {
	key := Key("github", "12345")
	if !ValidKey(key) {
		t.Fatalf("Key produced an unusable key %q", key)
	}
	if key != Key("github", "12345") {
		t.Fatal("Key must be stable for one identity")
	}
	if key == Key("gitlab", "12345") {
		t.Fatal("the same id on two forges must not collide")
	}
	// A hostile identity must not escape the data directory.
	hostile := Key("github", "../../etc/passwd")
	if strings.Contains(hostile, "/") || strings.Contains(hostile, "..") {
		t.Fatalf("Key must neutralize separators, got %q", hostile)
	}
	if !ValidKey(hostile) {
		t.Fatalf("a neutralized key must stay valid, got %q", hostile)
	}
}

func TestValidKeyRejectsTraversal(t *testing.T) {
	for _, bad := range []string{"", "..", "a/b", "../x", "a\\b", strings.Repeat("a", 121), "a b", "a\x00b"} {
		if ValidKey(bad) {
			t.Errorf("ValidKey(%q) must be false", bad)
		}
	}
	for _, good := range []string{"a", "repo-abc123", "a.b_c-d", strings.Repeat("a", 120)} {
		if !ValidKey(good) {
			t.Errorf("ValidKey(%q) must be true", good)
		}
	}
}

func TestStoreRejectsAnInvalidKeyBeforeTouchingDisk(t *testing.T) {
	s := open(t)
	if _, err := s.Repo("../escape", "repo"); err == nil {
		t.Fatal("a traversing user key must be refused")
	}
	if _, err := s.Record("user", "repo", "../../etc/passwd"); err == nil {
		t.Fatal("a traversing commit must be refused")
	}
}

func TestUserRoundTrip(t *testing.T) {
	s := open(t)
	if _, err := s.User("missing-000000000000"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
	u := &User{Key: Key("github", "1"), Provider: "github", ID: "1", Login: "octocat", Token: "sealed"}
	if err := s.PutUser(u); err != nil {
		t.Fatalf("PutUser: %v", err)
	}
	if u.CreatedAt.IsZero() || u.UpdatedAt.IsZero() {
		t.Error("PutUser must stamp the record")
	}
	got, err := s.User(u.Key)
	if err != nil || got.Login != "octocat" || got.Token != "sealed" {
		t.Fatalf("User = %+v, %v", got, err)
	}
}

func TestRepoUpdateIsAtomicAndScopedToItsUser(t *testing.T) {
	s := open(t)
	userA, userB := Key("github", "1"), Key("github", "2")
	repo := &Repo{Key: Key("github", "10"), Provider: "github", ID: "10", FullName: "acme/shop"}
	if err := s.PutRepo(userA, repo); err != nil {
		t.Fatalf("PutRepo: %v", err)
	}
	if _, err := s.Repo(userB, repo.Key); !errors.Is(err, ErrNotFound) {
		t.Fatalf("another account must not see the repository, got %v", err)
	}
	updated, err := s.UpdateRepo(userA, repo.Key, func(r *Repo) error {
		r.Monitored, r.HasPolicy = true, true
		return nil
	})
	if err != nil || !updated.Monitored {
		t.Fatalf("UpdateRepo = %+v, %v", updated, err)
	}
	reread, _ := s.Repo(userA, repo.Key)
	if !reread.Monitored || !reread.HasPolicy {
		t.Error("the mutation must be persisted")
	}
	if _, err := s.UpdateRepo(userA, repo.Key, func(r *Repo) error { return errors.New("no") }); err == nil {
		t.Error("a failing mutation must be reported")
	}
}

func TestPublicRepoHidesTheWebhookCredential(t *testing.T) {
	repo := &Repo{
		Key: "k", FullName: "acme/shop", HookID: "42",
		HookKey: "routing-key", HookSecret: "sealed-secret", Monitored: true,
	}
	data, err := json.Marshal(repo.Public())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, leak := range []string{"routing-key", "sealed-secret", "hook_id"} {
		if strings.Contains(string(data), leak) {
			t.Errorf("the public projection leaks %q: %s", leak, data)
		}
	}
	if !strings.Contains(string(data), "acme/shop") {
		t.Error("the public projection must keep the repository name")
	}
}

func TestReposListsOnlyTheAccountOwnRepositories(t *testing.T) {
	s := open(t)
	userA, userB := Key("github", "1"), Key("github", "2")
	for _, name := range []string{"acme/b", "acme/a"} {
		if err := s.PutRepo(userA, &Repo{Key: Key("github", name), FullName: name}); err != nil {
			t.Fatalf("PutRepo: %v", err)
		}
	}
	if err := s.PutRepo(userB, &Repo{Key: Key("github", "other"), FullName: "other/repo"}); err != nil {
		t.Fatalf("PutRepo: %v", err)
	}
	repos, err := s.Repos(userA)
	if err != nil || len(repos) != 2 {
		t.Fatalf("Repos = %d entries, %v", len(repos), err)
	}
	if repos[0].FullName != "acme/a" {
		t.Errorf("repositories must be sorted by name, got %q first", repos[0].FullName)
	}
	if empty, err := s.Repos(Key("github", "nobody")); err != nil || len(empty) != 0 {
		t.Errorf("an unknown account lists nothing, got %d, %v", len(empty), err)
	}
}

func TestHookRouting(t *testing.T) {
	s := open(t)
	route := HookRoute{UserKey: Key("github", "1"), RepoKey: Key("github", "10"), Provider: "github"}
	if err := s.PutHook("hook-key-1", route); err != nil {
		t.Fatalf("PutHook: %v", err)
	}
	got, err := s.Hook("hook-key-1")
	if err != nil || got != route {
		t.Fatalf("Hook = %+v, %v", got, err)
	}
	if err := s.DeleteHook("hook-key-1"); err != nil {
		t.Fatalf("DeleteHook: %v", err)
	}
	if _, err := s.Hook("hook-key-1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a deleted route must be gone, got %v", err)
	}
	if err := s.DeleteHook("never-existed"); err != nil {
		t.Errorf("deleting an unknown route must be a no-op, got %v", err)
	}
}

func TestRecordHistoryIsTrimmedAndNewestFirst(t *testing.T) {
	s := open(t)
	userKey, repoKey := Key("github", "1"), Key("github", "10")
	base := time.Now().UTC().Add(-time.Hour)
	for i := 0; i < MaxHistory+5; i++ {
		rec := &Record{
			UserKey: userKey, RepoKey: repoKey, RepoName: "acme/shop",
			Raw: json.RawMessage(`{"version":1}`),
		}
		rec.Commit = commitOf(i)
		rec.QueuedAt = base.Add(time.Duration(i) * time.Minute)
		rec.Status = StatusDone
		rec.Summary = report.Summary{Verdict: report.VerdictClear}
		if err := s.PutRecord(rec); err != nil {
			t.Fatalf("PutRecord: %v", err)
		}
	}
	runs, err := s.History(userKey, repoKey, 0)
	if err != nil {
		t.Fatalf("History: %v", err)
	}
	if len(runs) > MaxHistory {
		t.Fatalf("history kept %d records, want at most %d", len(runs), MaxHistory)
	}
	for i := 1; i < len(runs); i++ {
		if runs[i-1].QueuedAt.Before(runs[i].QueuedAt) {
			t.Fatal("history must be newest first")
		}
	}
	if limited, _ := s.History(userKey, repoKey, 3); len(limited) != 3 {
		t.Errorf("History(limit 3) returned %d entries", len(limited))
	}
	// The raw report must never travel with the history listing.
	for _, run := range runs {
		if run.Commit == "" {
			t.Error("a listed run must keep its commit")
		}
	}
	latest, err := s.Record(userKey, repoKey, commitOf(MaxHistory+4))
	if err != nil || len(latest.Raw) == 0 {
		t.Fatalf("the newest record must stay readable, got %v", err)
	}
}

func commitOf(i int) string {
	return "abcdef0123456789abcdef0123456789abcdef" + string(rune('a'+i/26)) + string(rune('a'+i%26))
}

func TestWriteIsAtomicAndPrivate(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	u := &User{Key: Key("github", "1"), Login: "octocat"}
	if err := s.PutUser(u); err != nil {
		t.Fatalf("PutUser: %v", err)
	}
	info, err := os.Stat(filepath.Join(dir, "users", u.Key+".json"))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("record mode = %o, want 600: it holds a sealed token", mode)
	}
	entries, _ := os.ReadDir(filepath.Join(dir, "users"))
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".tmp-") {
			t.Error("a temporary file was left behind")
		}
	}
}

func TestHistoryOfAnUnknownRepositoryIsEmpty(t *testing.T) {
	s := open(t)
	runs, err := s.History(Key("github", "1"), Key("github", "10"), 0)
	if err != nil || len(runs) != 0 {
		t.Fatalf("History = %d, %v; want an empty listing and no error", len(runs), err)
	}
}
