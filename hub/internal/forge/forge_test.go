package forge

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gvinsot/SwiftProof/hub/internal/config"
)

// Both providers must satisfy the interface the hub programs against.
var _ Provider = (*GitHub)(nil)
var _ Provider = (*GitLab)(nil)

func TestDetectLanguage(t *testing.T) {
	cases := []struct {
		entries []string
		want    string
	}{
		{[]string{"go.mod", "README.md"}, "go"},
		{[]string{"GO.MOD"}, "go"},
		{[]string{"package.json", "tsconfig.json"}, "typescript"},
		{[]string{"package.json"}, "javascript"},
		{[]string{"pyproject.toml"}, "python"},
		{[]string{"requirements.txt"}, "python"},
		{[]string{"Cargo.toml"}, "unknown"},
		{nil, "unknown"},
	}
	for _, c := range cases {
		if got := DetectLanguage(c.entries); got != c.want {
			t.Errorf("DetectLanguage(%v) = %q, want %q", c.entries, got, c.want)
		}
	}
}

func TestRedactDropsTheQueryString(t *testing.T) {
	got := redact("https://github.com/login/oauth/access_token?client_secret=shhh&code=abcd")
	if strings.Contains(got, "shhh") || strings.Contains(got, "abcd") {
		t.Fatalf("redact leaked credentials: %s", got)
	}
	if got != "https://github.com/login/oauth/access_token" {
		t.Fatalf("redact = %q", got)
	}
}

func TestPathEscapeKeepsSeparatorsAndEscapesSegments(t *testing.T) {
	if got := pathEscape(".swiftproof.json"); got != ".swiftproof.json" {
		t.Errorf("pathEscape = %q", got)
	}
	if got := pathEscape("dir/sub dir/file.json"); got != "dir/sub%20dir/file.json" {
		t.Errorf("pathEscape = %q", got)
	}
	if got := pathEscape("../../etc/passwd"); strings.Contains(got, "..%2F") {
		t.Errorf("pathEscape must not escape the separators themselves: %q", got)
	}
}

func TestTokenExpiry(t *testing.T) {
	now := time.Now()
	if (Token{AccessToken: "x"}).Expired(now) {
		t.Error("a token without expiry never expires")
	}
	if !(Token{Expiry: now.Add(30 * time.Second)}).Expired(now) {
		t.Error("a token expiring within the margin must be refreshed")
	}
	if (Token{Expiry: now.Add(time.Hour)}).Expired(now) {
		t.Error("a long-lived token must not be refreshed")
	}
}

/* ------------------------------------------------------------- webhooks -- */

func TestGitHubVerifyWebhook(t *testing.T) {
	g := NewGitHub(config.Forge{Kind: config.GitHub})
	body := []byte(`{"ref":"refs/heads/main"}`)
	mac := hmac.New(sha256.New, []byte("s3cret"))
	mac.Write(body)
	signature := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	r := httptest.NewRequest(http.MethodPost, "/hooks/x", nil)
	r.Header.Set("X-Hub-Signature-256", signature)
	if err := g.VerifyWebhook(r, body, "s3cret"); err != nil {
		t.Fatalf("a correct signature must be accepted: %v", err)
	}
	if err := g.VerifyWebhook(r, body, "other"); err == nil {
		t.Fatal("a wrong secret must be refused")
	}
	if err := g.VerifyWebhook(r, append(body, '!'), "s3cret"); err == nil {
		t.Fatal("a modified body must be refused")
	}
	bare := httptest.NewRequest(http.MethodPost, "/hooks/x", nil)
	if err := g.VerifyWebhook(bare, body, "s3cret"); err == nil {
		t.Fatal("a missing signature must be refused")
	}
	malformed := httptest.NewRequest(http.MethodPost, "/hooks/x", nil)
	malformed.Header.Set("X-Hub-Signature-256", "sha256=zzz")
	if err := g.VerifyWebhook(malformed, body, "s3cret"); err == nil {
		t.Fatal("a malformed signature must be refused")
	}
}

func TestGitLabVerifyWebhook(t *testing.T) {
	g := NewGitLab(config.Forge{Kind: config.GitLab})
	r := httptest.NewRequest(http.MethodPost, "/hooks/x", nil)
	r.Header.Set("X-Gitlab-Token", "s3cret")
	if err := g.VerifyWebhook(r, nil, "s3cret"); err != nil {
		t.Fatalf("the configured token must be accepted: %v", err)
	}
	if err := g.VerifyWebhook(r, nil, "other"); err == nil {
		t.Fatal("a wrong token must be refused")
	}
	bare := httptest.NewRequest(http.MethodPost, "/hooks/x", nil)
	if err := g.VerifyWebhook(bare, nil, "s3cret"); err == nil {
		t.Fatal("a missing token must be refused")
	}
}

func TestGitHubParsePush(t *testing.T) {
	g := NewGitHub(config.Forge{})
	body := []byte(`{
      "ref": "refs/heads/main", "before": "1111111111111111111111111111111111111111",
      "after": "2222222222222222222222222222222222222222", "deleted": false,
      "repository": {"id": 42, "full_name": "acme/shop", "default_branch": "main"},
      "head_commit": {"message": "fix refund\n\ndetails", "author": {"name": "Ada"}}
    }`)
	push, err := g.ParsePush(body)
	if err != nil {
		t.Fatalf("ParsePush: %v", err)
	}
	if push.RepoID != "42" || push.FullName != "acme/shop" || push.Default != "main" {
		t.Errorf("push = %+v", push)
	}
	if !push.IsBranch || push.IsDeletion {
		t.Errorf("a branch push must be analyzable: %+v", push)
	}
	if push.Author != "Ada" || !strings.HasPrefix(push.Message, "fix refund") {
		t.Errorf("push metadata = %+v", push)
	}

	deleted, err := g.ParsePush([]byte(`{"ref":"refs/heads/gone","after":"0000000000000000000000000000000000000000","deleted":true,"repository":{"id":42}}`))
	if err != nil || !deleted.IsDeletion {
		t.Errorf("a branch deletion must be recognized: %+v, %v", deleted, err)
	}
	tag, _ := g.ParsePush([]byte(`{"ref":"refs/tags/v1","after":"3333333333333333333333333333333333333333","repository":{"id":42}}`))
	if tag.IsBranch {
		t.Error("a tag push is not a branch push")
	}
	if _, err := g.ParsePush([]byte("not json")); err == nil {
		t.Error("a malformed payload must be refused")
	}
}

func TestGitLabParsePush(t *testing.T) {
	g := NewGitLab(config.Forge{})
	body := []byte(`{
      "object_kind": "push", "before": "1111111111111111111111111111111111111111",
      "after": "2222222222222222222222222222222222222222", "ref": "refs/heads/main",
      "user_name": "Ada Lovelace",
      "project": {"id": 7, "path_with_namespace": "acme/shop", "default_branch": "main"},
      "commits": [
        {"id": "1111111111111111111111111111111111111111", "message": "older", "author": {"name": "Bob"}},
        {"id": "2222222222222222222222222222222222222222", "message": "fix refund", "author": {"name": "Ada"}}
      ]
    }`)
	push, err := g.ParsePush(body)
	if err != nil {
		t.Fatalf("ParsePush: %v", err)
	}
	if push.RepoID != "7" || push.FullName != "acme/shop" || !push.IsBranch {
		t.Errorf("push = %+v", push)
	}
	if push.Message != "fix refund" || push.Author != "Ada" {
		t.Errorf("the head commit must be picked from the list, got %+v", push)
	}
}

/* ----------------------------------------------------------- API calls -- */

// fakeForge serves the handful of endpoints the hub uses.
func fakeForge(t *testing.T, routes map[string]func(w http.ResponseWriter, r *http.Request)) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	for pattern, handler := range routes {
		mux.HandleFunc(pattern, handler)
	}
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server
}

func TestGitHubReadFileAndCreateFile(t *testing.T) {
	var created map[string]any
	server := fakeForge(t, map[string]func(http.ResponseWriter, *http.Request){
		"/repos/acme/shop/contents/.swiftproof.json": func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPut {
				json.NewDecoder(r.Body).Decode(&created)
				w.WriteHeader(http.StatusCreated)
				w.Write([]byte(`{}`))
				return
			}
			if r.URL.Query().Get("ref") != "main" {
				t.Errorf("ref = %q, want main", r.URL.Query().Get("ref"))
			}
			w.Write([]byte(`{"content":"eyJ2ZXJzaW9uIjogMX0=","encoding":"base64"}`))
		},
		"/repos/acme/shop/contents/missing.json": func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, `{"message":"Not Found"}`, http.StatusNotFound)
		},
	})
	g := NewGitHub(config.Forge{APIURL: server.URL})
	repo := Repo{ID: "42", FullName: "acme/shop", DefaultBranch: "main"}

	content, found, err := g.ReadFile(context.Background(), Token{AccessToken: "t"}, repo, "main", ".swiftproof.json")
	if err != nil || !found || string(content) != `{"version": 1}` {
		t.Fatalf("ReadFile = %q, %v, %v", content, found, err)
	}
	_, found, err = g.ReadFile(context.Background(), Token{AccessToken: "t"}, repo, "main", "missing.json")
	if err != nil || found {
		t.Fatalf("a missing file must report found=false without an error, got %v, %v", found, err)
	}
	if err := g.CreateFile(context.Background(), Token{AccessToken: "t"}, repo, "main", ".swiftproof.json", "Add policy", []byte(`{"version":1}`)); err != nil {
		t.Fatalf("CreateFile: %v", err)
	}
	if created["branch"] != "main" || created["message"] != "Add policy" {
		t.Errorf("commit payload = %+v", created)
	}
	if created["content"] != "eyJ2ZXJzaW9uIjoxfQ==" {
		t.Errorf("the content must be base64 encoded, got %v", created["content"])
	}
}

func TestGitHubListReposSkipsArchived(t *testing.T) {
	server := fakeForge(t, map[string]func(http.ResponseWriter, *http.Request){
		"/user/repos": func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "Bearer t" {
				t.Errorf("missing credential: %q", r.Header.Get("Authorization"))
			}
			w.Write([]byte(`[
              {"id":1,"full_name":"acme/a","default_branch":"main","clone_url":"https://host/acme/a.git","permissions":{"admin":true}},
              {"id":2,"full_name":"acme/archived","archived":true},
              {"id":3,"full_name":"acme/b","default_branch":"dev","private":true,"permissions":{"admin":false,"push":true}}
            ]`))
		},
	})
	g := NewGitHub(config.Forge{APIURL: server.URL})
	repos, err := g.ListRepos(context.Background(), Token{AccessToken: "t"}, 100)
	if err != nil {
		t.Fatalf("ListRepos: %v", err)
	}
	if len(repos) != 2 {
		t.Fatalf("got %d repositories, want 2 (the archived one is skipped)", len(repos))
	}
	if !repos[0].Admin || repos[1].Admin {
		t.Errorf("admin flags = %v, %v", repos[0].Admin, repos[1].Admin)
	}
	if !repos[1].Private {
		t.Error("visibility must be preserved")
	}
}

func TestGitHubExchangeRefusesAnErrorResponse(t *testing.T) {
	server := fakeForge(t, map[string]func(http.ResponseWriter, *http.Request){
		"/login/oauth/access_token": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"error":"bad_verification_code","error_description":"code expired"}`))
		},
	})
	g := NewGitHub(config.Forge{BaseURL: server.URL})
	if _, err := g.Exchange(context.Background(), "code", "https://hub/cb"); err == nil {
		t.Fatal("an OAuth error must not yield a token")
	} else if strings.Contains(err.Error(), "code expired") {
		t.Fatalf("the provider description must not be echoed back: %v", err)
	}
}

func TestGitLabHeadCommitAndStatusMapping(t *testing.T) {
	var status map[string]string
	server := fakeForge(t, map[string]func(http.ResponseWriter, *http.Request){
		"/api/v4/projects/7/repository/commits/main": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"id":"cafebabe","message":"tip","author_name":"Ada"}`))
		},
		"/api/v4/projects/7/statuses/cafebabe": func(w http.ResponseWriter, r *http.Request) {
			json.NewDecoder(r.Body).Decode(&status)
			w.Write([]byte(`{}`))
		},
	})
	g := NewGitLab(config.Forge{BaseURL: server.URL, APIURL: server.URL + "/api/v4"})
	repo := Repo{ID: "7", FullName: "acme/shop"}

	head, err := g.HeadCommit(context.Background(), Token{AccessToken: "t"}, repo, "main")
	if err != nil || head.SHA != "cafebabe" || head.Author != "Ada" {
		t.Fatalf("HeadCommit = %+v, %v", head, err)
	}
	if err := g.SetStatus(context.Background(), Token{AccessToken: "t"}, repo, "cafebabe", StateFailure, "blocked", "https://hub/x"); err != nil {
		t.Fatalf("SetStatus: %v", err)
	}
	if status["state"] != "failed" {
		t.Errorf("GitLab uses \"failed\", got %q", status["state"])
	}
	if status["name"] != StatusContext {
		t.Errorf("status name = %q", status["name"])
	}
}

func TestGitAuthHeadersUseTheDocumentedBasicForm(t *testing.T) {
	gh := NewGitHub(config.Forge{}).GitAuthHeader(Token{AccessToken: "gho_x"})
	gl := NewGitLab(config.Forge{}).GitAuthHeader(Token{AccessToken: "glpat_x"})
	if !strings.HasPrefix(gh, "Basic ") || !strings.HasPrefix(gl, "Basic ") {
		t.Fatalf("headers = %q, %q", gh, gl)
	}
	if gh == gl {
		t.Fatal("the two forges use different basic-auth users")
	}
	if strings.Contains(gh, "gho_x") {
		t.Fatal("the token must be encoded, not concatenated in clear")
	}
}

func TestErrorCarriesTheStatus(t *testing.T) {
	server := fakeForge(t, map[string]func(http.ResponseWriter, *http.Request){
		"/user": func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, `{"message":"Bad credentials"}`, http.StatusUnauthorized)
		},
	})
	g := NewGitHub(config.Forge{APIURL: server.URL})
	_, err := g.CurrentUser(context.Background(), Token{AccessToken: "t"})
	if err == nil {
		t.Fatal("expected an error")
	}
	if got := StatusOf(err); got != http.StatusUnauthorized {
		t.Errorf("StatusOf = %d, want 401", got)
	}
}
