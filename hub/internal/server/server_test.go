package server

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gvinsot/SwiftProof/hub/internal/accounts"
	"github.com/gvinsot/SwiftProof/hub/internal/analysis"
	"github.com/gvinsot/SwiftProof/hub/internal/config"
	"github.com/gvinsot/SwiftProof/hub/internal/events"
	"github.com/gvinsot/SwiftProof/hub/internal/forge"
	"github.com/gvinsot/SwiftProof/hub/internal/secrets"
	"github.com/gvinsot/SwiftProof/hub/internal/store"
)

/* ------------------------------------------------------- a fake forge -- */

// fakeProvider records what the hub asked the forge to do.
type fakeProvider struct {
	mu          sync.Mutex
	kind        string
	files       map[string][]byte
	createdFile struct {
		branch, path, message string
		content               []byte
	}
	hookTarget string
	hookSecret string
	deleted    []string
	statuses   []string
	head       forge.Commit
	failCreate error
}

func newFakeProvider() *fakeProvider {
	return &fakeProvider{
		kind:  config.GitHub,
		files: map[string][]byte{},
		head:  forge.Commit{SHA: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2", Message: "tip", Author: "Ada"},
	}
}

func (f *fakeProvider) Kind() string { return f.kind }
func (f *fakeProvider) AuthURL(state, redirect string) string {
	return "https://forge.test/authorize?state=" + state
}
func (f *fakeProvider) Exchange(context.Context, string, string) (forge.Token, error) {
	return forge.Token{AccessToken: "access"}, nil
}
func (f *fakeProvider) Refresh(_ context.Context, t forge.Token) (forge.Token, error) { return t, nil }
func (f *fakeProvider) CurrentUser(context.Context, forge.Token) (forge.User, error) {
	return forge.User{ID: "1", Login: "octocat", Name: "Octo Cat"}, nil
}
func (f *fakeProvider) ListRepos(context.Context, forge.Token, int) ([]forge.Repo, error) {
	return []forge.Repo{{ID: "10", FullName: "acme/shop", DefaultBranch: "main", CloneURL: "https://forge.test/acme/shop.git", Admin: true}}, nil
}
func (f *fakeProvider) ReadFile(_ context.Context, _ forge.Token, _ forge.Repo, _, path string) ([]byte, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	data, ok := f.files[path]
	return data, ok, nil
}
func (f *fakeProvider) CreateFile(_ context.Context, _ forge.Token, _ forge.Repo, branch, path, message string, content []byte) error {
	if f.failCreate != nil {
		return f.failCreate
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.createdFile.branch, f.createdFile.path = branch, path
	f.createdFile.message, f.createdFile.content = message, content
	f.files[path] = content
	return nil
}
func (f *fakeProvider) ListRoot(context.Context, forge.Token, forge.Repo, string) ([]string, error) {
	return []string{"go.mod", "README.md"}, nil
}
func (f *fakeProvider) HeadCommit(context.Context, forge.Token, forge.Repo, string) (forge.Commit, error) {
	return f.head, nil
}
func (f *fakeProvider) CreateHook(_ context.Context, _ forge.Token, _ forge.Repo, target, secret string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hookTarget, f.hookSecret = target, secret
	return "hook-1", nil
}
func (f *fakeProvider) DeleteHook(_ context.Context, _ forge.Token, _ forge.Repo, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deleted = append(f.deleted, id)
	return nil
}
func (f *fakeProvider) SetStatus(_ context.Context, _ forge.Token, _ forge.Repo, sha, state, _, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.statuses = append(f.statuses, sha+":"+state)
	return nil
}
func (f *fakeProvider) GitAuthHeader(forge.Token) string { return "Basic x" }
func (f *fakeProvider) VerifyWebhook(r *http.Request, body []byte, secret string) error {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	if r.Header.Get("X-Test-Signature") != hex.EncodeToString(mac.Sum(nil)) {
		return fmt.Errorf("signature mismatch")
	}
	return nil
}
func (f *fakeProvider) ParsePush(body []byte) (forge.Push, error) {
	var p forge.Push
	if err := json.Unmarshal(body, &p); err != nil {
		return forge.Push{}, err
	}
	p.IsBranch = strings.HasPrefix(p.Ref, "refs/heads/")
	p.IsDeletion = strings.Trim(p.After, "0") == ""
	return p, nil
}

/* ------------------------------------------------------------ harness -- */

type harness struct {
	t        *testing.T
	server   *Server
	handler  http.Handler
	store    *store.Store
	keys     *secrets.Keyring
	provider *fakeProvider
	cfg      config.Config
	cookie   *http.Cookie
	csrf     string
	userKey  string
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	dir := t.TempDir()
	cfg := config.Config{
		Addr: ":0", BaseURL: "https://hub.example", DataDir: dir, Mode: config.ModeLint,
		Binary: "/bin/true", Workers: 1, QueueSize: 8, AnalysisTimeout: time.Minute,
		CloneDepth: 5, MaxRepos: 100, SessionTTL: time.Hour, CommitStatus: false,
		Forges: map[string]config.Forge{config.GitHub: {Kind: config.GitHub, ClientID: "id", ClientSecret: "s"}},
	}
	keys, err := secrets.New(bytes.Repeat([]byte{3}, 32))
	if err != nil {
		t.Fatalf("secrets.New: %v", err)
	}
	st, err := store.Open(dir)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	provider := newFakeProvider()
	acct := accounts.New(st, keys, map[string]forge.Provider{config.GitHub: provider})
	broker := events.New()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	runner := analysis.New(cfg, st, acct, broker, log)
	srv, err := New(cfg, st, acct, runner, broker, keys, log, "test")
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	return &harness{t: t, server: srv, handler: srv.Handler(), store: st, keys: keys, provider: provider, cfg: cfg}
}

// signIn creates a stored account and the matching session cookie.
func (h *harness) signIn() {
	h.t.Helper()
	key := store.Key(config.GitHub, "1")
	user := &store.User{Key: key, Provider: config.GitHub, ID: "1", Login: "octocat"}
	sealed, err := h.keys.Seal("access-token")
	if err != nil {
		h.t.Fatalf("seal: %v", err)
	}
	user.Token = sealed
	if err := h.store.PutUser(user); err != nil {
		h.t.Fatalf("PutUser: %v", err)
	}
	sess, err := secrets.NewSession(key, config.GitHub, "octocat", time.Hour, time.Now())
	if err != nil {
		h.t.Fatalf("NewSession: %v", err)
	}
	value, err := h.keys.SignSession(sess)
	if err != nil {
		h.t.Fatalf("SignSession: %v", err)
	}
	h.cookie = &http.Cookie{Name: sessionCookie, Value: value}
	h.csrf = h.keys.CSRF(sess)
	h.userKey = key
}

// do issues an authenticated request with the CSRF token attached.
func (h *harness) do(method, path string, body any) *httptest.ResponseRecorder {
	h.t.Helper()
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			h.t.Fatalf("marshal: %v", err)
		}
		reader = bytes.NewReader(encoded)
	}
	r := httptest.NewRequest(method, path, reader)
	if h.cookie != nil {
		r.AddCookie(h.cookie)
		r.Header.Set(csrfHeader, h.csrf)
	}
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	h.handler.ServeHTTP(w, r)
	return w
}

func (h *harness) decode(w *httptest.ResponseRecorder) map[string]any {
	h.t.Helper()
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		h.t.Fatalf("decode %s: %v", w.Body.String(), err)
	}
	return out
}

// awaitSync waits for the background repository sync of a user to finish, so
// a test never races the goroutine against its temporary data directory.
func (h *harness) awaitSync(userKey string, trigger func()) {
	h.t.Helper()
	stream, cancel := h.server.events.Subscribe(userKey)
	defer cancel()
	trigger()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case data, open := <-stream:
			if !open {
				return
			}
			var event struct {
				Type   string `json:"type"`
				Status string `json:"status"`
			}
			if json.Unmarshal(data, &event) == nil && event.Type == "sync" &&
				(event.Status == "finished" || event.Status == "failed") {
				return
			}
		case <-deadline:
			h.t.Fatal("the background repository sync did not finish")
		}
	}
}

// addRepo stores a repository owned by the signed-in account.
func (h *harness) addRepo(mutate func(*store.Repo)) *store.Repo {
	h.t.Helper()
	repo := &store.Repo{
		Key: store.Key(config.GitHub, "10"), Provider: config.GitHub, ID: "10",
		FullName: "acme/shop", WebURL: "https://forge.test/acme/shop",
		CloneURL: "https://forge.test/acme/shop.git", DefaultBranch: "main", Admin: true,
	}
	if mutate != nil {
		mutate(repo)
	}
	if err := h.store.PutRepo(h.userKey, repo); err != nil {
		h.t.Fatalf("PutRepo: %v", err)
	}
	return repo
}

/* -------------------------------------------------------------- tests -- */

func TestAnonymousAccess(t *testing.T) {
	h := newHarness(t)

	if got := h.do(http.MethodGet, "/api/repos", nil); got.Code != http.StatusUnauthorized {
		t.Errorf("GET /api/repos = %d, want 401", got.Code)
	}
	if got := h.do(http.MethodPost, "/api/repos/x/policy", map[string]any{}); got.Code != http.StatusUnauthorized {
		t.Errorf("POST policy = %d, want 401", got.Code)
	}
	me := h.decode(h.do(http.MethodGet, "/api/me", nil))
	if me["authenticated"] != false {
		t.Errorf("/api/me = %v, want authenticated false", me)
	}
	if forges, ok := me["forges"].([]any); !ok || len(forges) != 1 {
		t.Errorf("/api/me must advertise the configured forges, got %v", me["forges"])
	}

	page := h.do(http.MethodGet, "/", nil)
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), "SwiftProof Hub") {
		t.Errorf("the sign-in page must be served anonymously, got %d", page.Code)
	}
	if got := page.Header().Get("Content-Security-Policy"); !strings.Contains(got, "frame-ancestors 'none'") {
		t.Errorf("Content-Security-Policy = %q", got)
	}
	for header, want := range map[string]string{
		"X-Content-Type-Options": "nosniff",
		"Referrer-Policy":        "no-referrer",
		"X-Frame-Options":        "DENY",
	} {
		if got := page.Header().Get(header); got != want {
			t.Errorf("%s = %q, want %q", header, got, want)
		}
	}
}

func TestSignInFlow(t *testing.T) {
	h := newHarness(t)

	start := h.do(http.MethodGet, "/auth/github/start", nil)
	if start.Code != http.StatusFound {
		t.Fatalf("start = %d, want a redirect", start.Code)
	}
	var state string
	for _, c := range start.Result().Cookies() {
		if c.Name == stateCookie {
			state = c.Value
		}
	}
	if state == "" {
		t.Fatal("the flow must pin its state to a cookie")
	}
	if !strings.Contains(start.Header().Get("Location"), state) {
		t.Error("the state must travel to the forge")
	}
	if got := h.do(http.MethodGet, "/auth/bitbucket/start", nil); got.Code != http.StatusNotFound {
		t.Errorf("an unconfigured forge = %d, want 404", got.Code)
	}

	// A callback without the matching cookie is refused.
	r := httptest.NewRequest(http.MethodGet, "/auth/github/callback?code=c&state="+state, nil)
	w := httptest.NewRecorder()
	h.handler.ServeHTTP(w, r)
	if !strings.Contains(w.Header().Get("Location"), "/index.html?error=") {
		t.Errorf("a callback without its cookie must fail, got %q", w.Header().Get("Location"))
	}

	// The complete callback opens a session and starts the first listing.
	w = httptest.NewRecorder()
	h.awaitSync(store.Key(config.GitHub, "1"), func() {
		r = httptest.NewRequest(http.MethodGet, "/auth/github/callback?code=c&state="+state, nil)
		r.AddCookie(&http.Cookie{Name: stateCookie, Value: state})
		h.handler.ServeHTTP(w, r)
	})
	if w.Code != http.StatusFound || w.Header().Get("Location") != "/app.html" {
		t.Fatalf("callback = %d, %q", w.Code, w.Header().Get("Location"))
	}
	var session *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == sessionCookie && c.Value != "" {
			session = c
		}
	}
	if session == nil {
		t.Fatal("the callback must set a session cookie")
	}
	if !session.HttpOnly || !session.Secure || session.SameSite != http.SameSiteLaxMode {
		t.Errorf("session cookie flags = %+v", session)
	}
	stored, err := h.store.User(store.Key(config.GitHub, "1"))
	if err != nil {
		t.Fatalf("the account must be stored: %v", err)
	}
	if stored.Token == "access" || stored.Token == "" {
		t.Errorf("the token must be sealed at rest, got %q", stored.Token)
	}
	if opened, err := h.keys.Open(stored.Token); err != nil || opened != "access" {
		t.Errorf("the sealed token must reopen to the credential, got %q, %v", opened, err)
	}
}

func TestCSRFAndOriginAreEnforced(t *testing.T) {
	h := newHarness(t)
	h.signIn()
	h.addRepo(nil)

	r := httptest.NewRequest(http.MethodPost, "/api/repos/sync", nil)
	r.AddCookie(h.cookie)
	w := httptest.NewRecorder()
	h.handler.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("a POST without the CSRF token = %d, want 403", w.Code)
	}

	r = httptest.NewRequest(http.MethodPost, "/api/repos/sync", nil)
	r.AddCookie(h.cookie)
	r.Header.Set(csrfHeader, h.csrf)
	r.Header.Set("Origin", "https://evil.example")
	w = httptest.NewRecorder()
	h.handler.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("a cross-origin POST = %d, want 403", w.Code)
	}

	h.awaitSync(h.userKey, func() {
		if got := h.do(http.MethodPost, "/api/repos/sync", nil); got.Code != http.StatusAccepted {
			t.Errorf("a legitimate POST = %d, want 202", got.Code)
		}
	})
	// A GET needs no token.
	if got := h.do(http.MethodGet, "/api/repos", nil); got.Code != http.StatusOK {
		t.Errorf("GET /api/repos = %d", got.Code)
	}
}

func TestPolicyBootstrap(t *testing.T) {
	h := newHarness(t)
	h.signIn()
	repo := h.addRepo(nil)
	// The generated policy comes from the CLI; stand in for it here.
	h.server.runner = newFakeRunner(t, h)

	preview := h.do(http.MethodPost, "/api/repos/"+repo.Key+"/policy", map[string]any{"preview": true})
	if preview.Code != http.StatusOK {
		t.Fatalf("preview = %d: %s", preview.Code, preview.Body)
	}
	body := h.decode(preview)
	if body["language"] != "go" {
		t.Errorf("language = %v, want go detected from go.mod", body["language"])
	}
	if !strings.Contains(body["policy"].(string), `"version"`) {
		t.Errorf("policy = %v", body["policy"])
	}
	if h.provider.createdFile.path != "" {
		t.Fatal("a preview must not commit anything")
	}
	if stored, _ := h.store.Repo(h.userKey, repo.Key); stored.HasPolicy {
		t.Fatal("a preview must not mark the repository as configured")
	}

	created := h.do(http.MethodPost, "/api/repos/"+repo.Key+"/policy", map[string]any{})
	if created.Code != http.StatusCreated {
		t.Fatalf("create = %d: %s", created.Code, created.Body)
	}
	if h.provider.createdFile.path != forge.PolicyPath || h.provider.createdFile.branch != "main" {
		t.Errorf("the policy must be committed on the default branch, got %+v", h.provider.createdFile)
	}
	if !strings.Contains(h.provider.createdFile.message, "SwiftProof") {
		t.Errorf("commit message = %q", h.provider.createdFile.message)
	}
	stored, _ := h.store.Repo(h.userKey, repo.Key)
	if !stored.HasPolicy {
		t.Error("the repository must be marked as configured")
	}

	again := h.do(http.MethodPost, "/api/repos/"+repo.Key+"/policy", map[string]any{})
	if again.Code != http.StatusConflict {
		t.Errorf("a second creation = %d, want 409", again.Code)
	}
	bad := h.do(http.MethodPost, "/api/repos/"+repo.Key+"/policy", map[string]any{"language": "cobol"})
	if bad.Code != http.StatusBadRequest {
		t.Errorf("an unsupported language = %d, want 400", bad.Code)
	}
}

func TestMonitoringLifecycle(t *testing.T) {
	h := newHarness(t)
	h.signIn()
	repo := h.addRepo(nil)

	if got := h.do(http.MethodPost, "/api/repos/"+repo.Key+"/monitor", nil); got.Code != http.StatusConflict {
		t.Fatalf("monitoring without a policy = %d, want 409", got.Code)
	}

	repo = h.addRepo(func(r *store.Repo) { r.HasPolicy = true; r.Admin = false })
	if got := h.do(http.MethodPost, "/api/repos/"+repo.Key+"/monitor", nil); got.Code != http.StatusForbidden {
		t.Fatalf("monitoring without admin rights = %d, want 403", got.Code)
	}

	repo = h.addRepo(func(r *store.Repo) { r.HasPolicy = true; r.Admin = true })
	on := h.do(http.MethodPost, "/api/repos/"+repo.Key+"/monitor", nil)
	if on.Code != http.StatusOK {
		t.Fatalf("monitor = %d: %s", on.Code, on.Body)
	}
	stored, _ := h.store.Repo(h.userKey, repo.Key)
	if !stored.Monitored || stored.HookID != "hook-1" || stored.HookKey == "" {
		t.Fatalf("monitoring state = %+v", stored)
	}
	if !strings.HasPrefix(h.provider.hookTarget, "https://hub.example/hooks/") {
		t.Errorf("hook target = %q", h.provider.hookTarget)
	}
	if len(h.provider.hookSecret) < 20 {
		t.Errorf("the webhook secret must be unguessable, got %q", h.provider.hookSecret)
	}
	if secret, err := h.keys.Open(stored.HookSecret); err != nil || secret != h.provider.hookSecret {
		t.Errorf("the webhook secret must be sealed at rest, got %q, %v", secret, err)
	}
	route, err := h.store.Hook(stored.HookKey)
	if err != nil || route.RepoKey != repo.Key {
		t.Fatalf("the routing key must resolve to the repository, got %+v, %v", route, err)
	}
	// The public projection must never carry the hook credentials.
	payload := h.decode(on)
	if strings.Contains(on.Body.String(), stored.HookKey) || strings.Contains(on.Body.String(), stored.HookSecret) {
		t.Errorf("the response leaks the webhook credentials: %v", payload)
	}

	off := h.do(http.MethodDelete, "/api/repos/"+repo.Key+"/monitor", nil)
	if off.Code != http.StatusOK {
		t.Fatalf("stop monitoring = %d", off.Code)
	}
	stopped, _ := h.store.Repo(h.userKey, repo.Key)
	if stopped.Monitored || stopped.HookID != "" {
		t.Errorf("state after stopping = %+v", stopped)
	}
	if len(h.provider.deleted) != 1 || h.provider.deleted[0] != "hook-1" {
		t.Errorf("the forge hook must be removed, got %v", h.provider.deleted)
	}
	if _, err := h.store.Hook(stored.HookKey); err == nil {
		t.Error("the routing key must be forgotten")
	}
}

func TestWebhookDelivery(t *testing.T) {
	h := newHarness(t)
	h.signIn()
	repo := h.addRepo(func(r *store.Repo) { r.HasPolicy = true; r.Admin = true })
	if got := h.do(http.MethodPost, "/api/repos/"+repo.Key+"/monitor", nil); got.Code != http.StatusOK {
		t.Fatalf("monitor = %d: %s", got.Code, got.Body)
	}
	stored, _ := h.store.Repo(h.userKey, repo.Key)
	hookKey, secret := stored.HookKey, h.provider.hookSecret

	post := func(key, secret string, payload forge.Push) *httptest.ResponseRecorder {
		body, _ := json.Marshal(payload)
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write(body)
		r := httptest.NewRequest(http.MethodPost, "/hooks/"+key, bytes.NewReader(body))
		r.Header.Set("X-Test-Signature", hex.EncodeToString(mac.Sum(nil)))
		r.Header.Set("X-GitHub-Event", "push")
		w := httptest.NewRecorder()
		h.handler.ServeHTTP(w, r)
		return w
	}

	push := forge.Push{RepoID: "10", Ref: "refs/heads/main", Before: strings.Repeat("1", 40), After: strings.Repeat("2", 40)}
	if got := post(hookKey, secret, push); got.Code != http.StatusAccepted {
		t.Errorf("a signed push = %d: %s", got.Code, got.Body)
	}
	if got := post(hookKey, "wrong-secret", push); got.Code != http.StatusUnauthorized {
		t.Errorf("a wrong signature = %d, want 401", got.Code)
	}
	if got := post("unknown-routing-key", secret, push); got.Code != http.StatusNotFound {
		t.Errorf("an unknown routing key = %d, want 404", got.Code)
	}

	deletion := push
	deletion.After = strings.Repeat("0", 40)
	if got := post(hookKey, secret, deletion); got.Code != http.StatusAccepted ||
		!strings.Contains(got.Body.String(), "ignored") {
		t.Errorf("a branch deletion must be ignored, got %d %s", got.Code, got.Body)
	}
	tag := push
	tag.Ref = "refs/tags/v1"
	if got := post(hookKey, secret, tag); !strings.Contains(got.Body.String(), "ignored") {
		t.Errorf("a tag push must be ignored, got %s", got.Body)
	}
	mismatch := push
	mismatch.RepoID = "999"
	if got := post(hookKey, secret, mismatch); got.Code != http.StatusBadRequest {
		t.Errorf("a payload for another repository = %d, want 400", got.Code)
	}

	// With the default-branch restriction, a feature branch is skipped.
	h.server.cfg.DefaultBranchOnly = true
	feature := push
	feature.Ref = "refs/heads/feature"
	if got := post(hookKey, secret, feature); !strings.Contains(got.Body.String(), "ignored") {
		t.Errorf("a non-default branch must be ignored, got %s", got.Body)
	}
}

func TestReportViewAndDownload(t *testing.T) {
	h := newHarness(t)
	h.signIn()
	repo := h.addRepo(func(r *store.Repo) { r.HasPolicy = true })
	commit := strings.Repeat("a", 40)
	rec := &store.Record{UserKey: h.userKey, RepoKey: repo.Key, RepoName: repo.FullName, Raw: json.RawMessage(storedReport)}
	rec.Commit = commit
	rec.Status = store.StatusDone
	rec.QueuedAt = time.Now().UTC()
	if err := h.store.PutRecord(rec); err != nil {
		t.Fatalf("PutRecord: %v", err)
	}

	runs := h.decode(h.do(http.MethodGet, "/api/repos/"+repo.Key+"/runs", nil))
	if list, ok := runs["runs"].([]any); !ok || len(list) != 1 {
		t.Fatalf("runs = %v", runs["runs"])
	}

	got := h.do(http.MethodGet, "/api/repos/"+repo.Key+"/reports/"+commit, nil)
	if got.Code != http.StatusOK {
		t.Fatalf("report = %d: %s", got.Code, got.Body)
	}
	payload := h.decode(got)
	view := payload["view"].(map[string]any)
	alerts := view["alerts"].([]any)
	if len(alerts) == 0 {
		t.Fatal("the view must carry the alerts")
	}
	first := alerts[0].(map[string]any)
	if first["severity"] != "high" {
		t.Errorf("the most severe alert must come first, got %v", first)
	}
	files := view["files"].([]any)
	if len(files) != 1 {
		t.Fatalf("the modifications must travel with the view, got %v", files)
	}
	if levels := view["severity_levels"].([]any); len(levels) != 4 {
		t.Errorf("the filter needs the four levels, got %v", levels)
	}

	raw := h.do(http.MethodGet, "/api/repos/"+repo.Key+"/reports/"+commit+"/raw", nil)
	if raw.Code != http.StatusOK {
		t.Fatalf("raw = %d", raw.Code)
	}
	if !strings.Contains(raw.Header().Get("Content-Disposition"), commit) {
		t.Errorf("Content-Disposition = %q", raw.Header().Get("Content-Disposition"))
	}
	var downloaded, original map[string]any
	if err := json.Unmarshal(raw.Body.Bytes(), &downloaded); err != nil {
		t.Fatalf("the download must be valid JSON: %v", err)
	}
	if err := json.Unmarshal([]byte(storedReport), &original); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	if fmt.Sprint(downloaded) != fmt.Sprint(original) {
		t.Error("the download must carry the confidence report the CLI produced, unaltered")
	}

	missing := h.do(http.MethodGet, "/api/repos/"+repo.Key+"/reports/"+strings.Repeat("b", 40), nil)
	if missing.Code != http.StatusNotFound {
		t.Errorf("an unknown commit = %d, want 404", missing.Code)
	}
	traversal := h.do(http.MethodGet, "/api/repos/"+repo.Key+"/reports/..%2f..%2fsession.key", nil)
	if traversal.Code == http.StatusOK {
		t.Errorf("a traversing commit must never be served, got %d", traversal.Code)
	}
}

func TestOneAccountCannotReachAnother(t *testing.T) {
	h := newHarness(t)
	h.signIn()
	victim := h.userKey
	repo := &store.Repo{Key: store.Key(config.GitHub, "99"), Provider: config.GitHub, ID: "99", FullName: "victim/private"}
	if err := h.store.PutRepo(victim, repo); err != nil {
		t.Fatalf("PutRepo: %v", err)
	}

	// Sign in as somebody else, keeping the same store.
	other := store.Key(config.GitHub, "2")
	sealed, _ := h.keys.Seal("access-token")
	if err := h.store.PutUser(&store.User{Key: other, Provider: config.GitHub, ID: "2", Login: "mallory", Token: sealed}); err != nil {
		t.Fatalf("PutUser: %v", err)
	}
	sess, _ := secrets.NewSession(other, config.GitHub, "mallory", time.Hour, time.Now())
	value, _ := h.keys.SignSession(sess)
	h.cookie = &http.Cookie{Name: sessionCookie, Value: value}
	h.csrf = h.keys.CSRF(sess)

	if got := h.do(http.MethodGet, "/api/repos/"+repo.Key, nil); got.Code != http.StatusNotFound {
		t.Errorf("reading another account's repository = %d, want 404", got.Code)
	}
	if got := h.do(http.MethodPost, "/api/repos/"+repo.Key+"/monitor", nil); got.Code != http.StatusNotFound {
		t.Errorf("monitoring another account's repository = %d, want 404", got.Code)
	}
	list := h.decode(h.do(http.MethodGet, "/api/repos", nil))
	if repos, ok := list["repos"].([]any); !ok || len(repos) != 0 {
		t.Errorf("the other account must see nothing, got %v", list["repos"])
	}
}

func TestBadgeReflectsTheLatestRun(t *testing.T) {
	h := newHarness(t)
	h.signIn()
	repo := h.addRepo(func(r *store.Repo) {
		r.HasPolicy, r.Monitored, r.HookKey = true, true, "badge-key"
		r.Latest = &store.Run{Commit: "abc", Status: store.StatusDone}
		r.Latest.Summary.Verdict = "blocked"
	})
	if err := h.store.PutHook("badge-key", store.HookRoute{UserKey: h.userKey, RepoKey: repo.Key, Provider: config.GitHub}); err != nil {
		t.Fatalf("PutHook: %v", err)
	}
	r := httptest.NewRequest(http.MethodGet, "/badge/badge-key.svg", nil)
	w := httptest.NewRecorder()
	h.handler.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("badge = %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "image/svg+xml") {
		t.Errorf("Content-Type = %q", ct)
	}
	if !strings.Contains(w.Body.String(), "reproduced issue") {
		t.Errorf("badge = %s", w.Body)
	}
	unknown := httptest.NewRequest(http.MethodGet, "/badge/nope.svg", nil)
	uw := httptest.NewRecorder()
	h.handler.ServeHTTP(uw, unknown)
	if uw.Code != http.StatusOK || !strings.Contains(uw.Body.String(), "unknown") {
		t.Errorf("an unknown badge must stay renderable, got %d %s", uw.Code, uw.Body)
	}
}

func TestBadgeSVGEscapesItsInput(t *testing.T) {
	svg := badgeSVG("swiftproof", `"><script>alert(1)</script>`, "#000")
	if strings.Contains(svg, "<script>") {
		t.Fatalf("the badge must escape its value: %s", svg)
	}
}

func TestEventStreamIsPerAccount(t *testing.T) {
	h := newHarness(t)
	h.signIn()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	r := httptest.NewRequest(http.MethodGet, "/api/events", nil).WithContext(ctx)
	r.AddCookie(h.cookie)
	w := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		h.handler.ServeHTTP(w, r)
		close(done)
	}()
	// Wait for the subscription, publish, then close the stream.
	deadline := time.Now().Add(2 * time.Second)
	for h.server.events.Subscribers() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	h.server.events.Publish(h.userKey, map[string]string{"type": "repo"})
	h.server.events.Publish("another-account", map[string]string{"type": "secret"})
	time.Sleep(50 * time.Millisecond)
	cancel()
	<-done

	body := w.Body.String()
	if !strings.Contains(body, `"type":"repo"`) {
		t.Errorf("the stream must carry the events of the account: %s", body)
	}
	if strings.Contains(body, "secret") {
		t.Errorf("the stream must not carry another account's events: %s", body)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Errorf("Content-Type = %q", ct)
	}
}

func TestSafeNext(t *testing.T) {
	for _, bad := range []string{"https://evil.example", "//evil.example", "app.html", "/a\nb", ""} {
		if got := safeNext(bad); got != "" {
			t.Errorf("safeNext(%q) = %q, want an empty redirect", bad, got)
		}
	}
	if got := safeNext("/app.html#/repo/x"); got != "/app.html#/repo/x" {
		t.Errorf("safeNext = %q", got)
	}
}

func TestHealth(t *testing.T) {
	h := newHarness(t)
	body := h.decode(h.do(http.MethodGet, "/healthz", nil))
	if body["status"] != "ok" || body["mode"] != config.ModeLint {
		t.Errorf("/healthz = %v", body)
	}
}

/* ----------------------------------------------------------- fixtures -- */

// newFakeRunner replaces the analysis runner with one whose CLI is a stub, so
// the policy endpoints can be exercised without the real binary.
func newFakeRunner(t *testing.T, h *harness) *analysis.Runner {
	t.Helper()
	dir := t.TempDir()
	script := "#!/bin/sh\nwhile [ $# -gt 0 ]; do case \"$1\" in --repo) d=\"$2\"; shift 2;; --language) l=\"$2\"; shift 2;; *) shift;; esac; done\n" +
		"printf '{\"version\":1,\"language\":\"%s\"}' \"$l\" > \"$d/.swiftproof.json\"\n"
	path := dir + "/swiftproof"
	if err := writeExecutable(path, script); err != nil {
		t.Skipf("cannot install the stub CLI here: %v", err)
	}
	cfg := h.cfg
	cfg.Binary = path
	acct := accounts.New(h.store, h.keys, map[string]forge.Provider{config.GitHub: h.provider})
	return analysis.New(cfg, h.store, acct, h.server.events, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

// writeExecutable installs a stub binary the runner can execute.
func writeExecutable(path, script string) error {
	return os.WriteFile(path, []byte(script), 0o700)
}

const storedReport = `{"version":1,"tool_version":"v0.3.1","generated_at":"2026-09-25T10:00:00Z",
"change":{"base_ref":"main","head_ref":"HEAD","base_commit":"aaa","head_commit":"bbb","additions":1,"deletions":1,
"files":[{"path":"pay/refund.go","status":"M","binary":false,"additions":1,"deletions":1,
"hunks":[{"old_start":1,"old_lines":1,"new_start":1,"new_lines":1,"lines":[
{"kind":"delete","old_line":1,"content":"check(amount)"},{"kind":"add","new_line":1,"content":"// removed"}]}]}]},
"linter":[{"id":"s1","kind":"removed_validation","path":"pay/refund.go","line":1,"severity":"high","summary":"validation removed","evidence":"the guard disappeared"}],
"checks":[],"hypotheses":[],"evidence":[],"reproduced_issues":[],"unverified":[],
"review_targets":[],"review_surface":{"changed_lines":2,"focused_lines":1,"note":"prioritization"},
"coverage":{"status":"not_configured","added_lines":0,"executed_lines":0,"not_executed_lines":0,"no_block_lines":0,"not_measured_lines":0,"removed_lines":0,"files":[],"note":""},
"artifacts":[],"audit":[],"exit_code":2}`
