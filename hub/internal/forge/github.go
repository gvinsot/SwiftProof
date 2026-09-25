package forge

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gvinsot/SwiftProof/hub/internal/config"
)

// GitHub speaks the REST API of github.com and of a GitHub Enterprise Server
// host, which only differ by their base URLs.
type GitHub struct {
	cfg    config.Forge
	client *client
}

// NewGitHub builds the github.com / GHES provider.
func NewGitHub(cfg config.Forge) *GitHub { return &GitHub{cfg: cfg, client: newClient()} }

func (g *GitHub) Kind() string { return config.GitHub }

func (g *GitHub) AuthURL(state, redirect string) string {
	q := url.Values{
		"client_id":    {g.cfg.ClientID},
		"redirect_uri": {redirect},
		"scope":        {strings.ReplaceAll(g.cfg.Scopes, ",", " ")},
		"state":        {state},
	}
	return g.cfg.BaseURL + "/login/oauth/authorize?" + q.Encode()
}

type githubToken struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
	TokenType    string `json:"token_type"`
	Error        string `json:"error"`
	ErrorDesc    string `json:"error_description"`
}

func (g *GitHub) Exchange(ctx context.Context, code, redirect string) (Token, error) {
	return g.token(ctx, url.Values{
		"client_id":     {g.cfg.ClientID},
		"client_secret": {g.cfg.ClientSecret},
		"code":          {code},
		"redirect_uri":  {redirect},
		"grant_type":    {"authorization_code"},
	})
}

// Refresh applies only when the OAuth app opted into expiring tokens; classic
// GitHub tokens have no refresh token and never expire.
func (g *GitHub) Refresh(ctx context.Context, token Token) (Token, error) {
	if token.RefreshToken == "" {
		return token, fmt.Errorf("github: no refresh token")
	}
	return g.token(ctx, url.Values{
		"client_id":     {g.cfg.ClientID},
		"client_secret": {g.cfg.ClientSecret},
		"refresh_token": {token.RefreshToken},
		"grant_type":    {"refresh_token"},
	})
}

func (g *GitHub) token(ctx context.Context, values url.Values) (Token, error) {
	var out githubToken
	_, err := g.client.do(ctx, request{
		method: http.MethodPost,
		url:    g.cfg.BaseURL + "/login/oauth/access_token",
		accept: "application/json",
		ctype:  "application/x-www-form-urlencoded",
		body:   form(values),
	}, &out)
	if err != nil {
		return Token{}, err
	}
	if out.Error != "" || out.AccessToken == "" {
		// The description can echo back request values, so it is not surfaced.
		return Token{}, fmt.Errorf("github: authorization failed (%s)", out.Error)
	}
	t := Token{AccessToken: out.AccessToken, RefreshToken: out.RefreshToken}
	if out.ExpiresIn > 0 {
		t.Expiry = time.Now().Add(time.Duration(out.ExpiresIn) * time.Second)
	}
	return t, nil
}

const githubAccept = "application/vnd.github+json"

func (g *GitHub) api(ctx context.Context, method, path, token string, body any, out any) (int, error) {
	r := request{
		method:  method,
		url:     g.cfg.APIURL + path,
		token:   token,
		accept:  githubAccept,
		headers: map[string]string{"X-GitHub-Api-Version": "2022-11-28"},
	}
	if body != nil {
		encoded, err := jsonBody(body)
		if err != nil {
			return 0, err
		}
		r.body, r.ctype = encoded, "application/json"
	}
	return g.client.do(ctx, r, out)
}

func (g *GitHub) CurrentUser(ctx context.Context, token Token) (User, error) {
	var out struct {
		ID        int64  `json:"id"`
		Login     string `json:"login"`
		Name      string `json:"name"`
		AvatarURL string `json:"avatar_url"`
		HTMLURL   string `json:"html_url"`
	}
	if _, err := g.api(ctx, http.MethodGet, "/user", token.AccessToken, nil, &out); err != nil {
		return User{}, err
	}
	return User{ID: strconv.FormatInt(out.ID, 10), Login: out.Login, Name: out.Name, AvatarURL: out.AvatarURL, WebURL: out.HTMLURL}, nil
}

type githubRepo struct {
	ID            int64  `json:"id"`
	FullName      string `json:"full_name"`
	HTMLURL       string `json:"html_url"`
	CloneURL      string `json:"clone_url"`
	DefaultBranch string `json:"default_branch"`
	Private       bool   `json:"private"`
	Archived      bool   `json:"archived"`
	Permissions   struct {
		Admin bool `json:"admin"`
		Push  bool `json:"push"`
	} `json:"permissions"`
}

func (g *GitHub) ListRepos(ctx context.Context, token Token, max int) ([]Repo, error) {
	repos := make([]Repo, 0, 64)
	for page := 1; page <= 20 && len(repos) < max; page++ {
		var out []githubRepo
		path := fmt.Sprintf("/user/repos?per_page=100&page=%d&sort=pushed&affiliation=owner,organization_member", page)
		if _, err := g.api(ctx, http.MethodGet, path, token.AccessToken, nil, &out); err != nil {
			return nil, err
		}
		for _, r := range out {
			if r.Archived {
				continue
			}
			repos = append(repos, Repo{
				ID:            strconv.FormatInt(r.ID, 10),
				FullName:      r.FullName,
				WebURL:        r.HTMLURL,
				CloneURL:      r.CloneURL,
				DefaultBranch: r.DefaultBranch,
				Private:       r.Private,
				Admin:         r.Permissions.Admin,
			})
		}
		if len(out) < 100 {
			break
		}
	}
	if len(repos) > max {
		repos = repos[:max]
	}
	return repos, nil
}

func (g *GitHub) ReadFile(ctx context.Context, token Token, repo Repo, ref, path string) ([]byte, bool, error) {
	var out struct {
		Content  string `json:"content"`
		Encoding string `json:"encoding"`
	}
	target := fmt.Sprintf("/repos/%s/contents/%s?ref=%s", repo.FullName, pathEscape(path), url.QueryEscape(ref))
	status, err := g.api(ctx, http.MethodGet, target, token.AccessToken, nil, &out)
	if status == http.StatusNotFound {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if out.Encoding != "base64" {
		return nil, true, nil
	}
	data, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(out.Content, "\n", ""))
	if err != nil {
		return nil, true, fmt.Errorf("github: decode %s: %w", path, err)
	}
	return data, true, nil
}

func (g *GitHub) CreateFile(ctx context.Context, token Token, repo Repo, branch, path, message string, content []byte) error {
	body := map[string]any{
		"message": message,
		"content": base64.StdEncoding.EncodeToString(content),
		"branch":  branch,
	}
	_, err := g.api(ctx, http.MethodPut, "/repos/"+repo.FullName+"/contents/"+pathEscape(path), token.AccessToken, body, nil)
	return err
}

func (g *GitHub) ListRoot(ctx context.Context, token Token, repo Repo, ref string) ([]string, error) {
	var out []struct {
		Name string `json:"name"`
	}
	target := fmt.Sprintf("/repos/%s/contents/?ref=%s", repo.FullName, url.QueryEscape(ref))
	if _, err := g.api(ctx, http.MethodGet, target, token.AccessToken, nil, &out); err != nil {
		return nil, err
	}
	names := make([]string, 0, len(out))
	for _, e := range out {
		names = append(names, e.Name)
	}
	return names, nil
}

func (g *GitHub) HeadCommit(ctx context.Context, token Token, repo Repo, ref string) (Commit, error) {
	var out struct {
		SHA    string `json:"sha"`
		Commit struct {
			Message string `json:"message"`
			Author  struct {
				Name string `json:"name"`
			} `json:"author"`
		} `json:"commit"`
	}
	target := "/repos/" + repo.FullName + "/commits/" + url.PathEscape(ref)
	if _, err := g.api(ctx, http.MethodGet, target, token.AccessToken, nil, &out); err != nil {
		return Commit{}, err
	}
	if out.SHA == "" {
		return Commit{}, fmt.Errorf("github: %s has no commit on %s", repo.FullName, ref)
	}
	return Commit{SHA: out.SHA, Message: out.Commit.Message, Author: out.Commit.Author.Name}, nil
}

func (g *GitHub) CreateHook(ctx context.Context, token Token, repo Repo, target, secret string) (string, error) {
	body := map[string]any{
		"name":   "web",
		"active": true,
		"events": []string{"push"},
		"config": map[string]string{
			"url":          target,
			"content_type": "json",
			"secret":       secret,
			"insecure_ssl": "0",
		},
	}
	var out struct {
		ID int64 `json:"id"`
	}
	if _, err := g.api(ctx, http.MethodPost, "/repos/"+repo.FullName+"/hooks", token.AccessToken, body, &out); err != nil {
		return "", err
	}
	return strconv.FormatInt(out.ID, 10), nil
}

func (g *GitHub) DeleteHook(ctx context.Context, token Token, repo Repo, id string) error {
	if id == "" {
		return nil
	}
	status, err := g.api(ctx, http.MethodDelete, "/repos/"+repo.FullName+"/hooks/"+url.PathEscape(id), token.AccessToken, nil, nil)
	if status == http.StatusNotFound {
		return nil
	}
	return err
}

func (g *GitHub) SetStatus(ctx context.Context, token Token, repo Repo, sha, state, description, targetURL string) error {
	body := map[string]string{
		"state":       state,
		"context":     StatusContext,
		"description": truncate(description, 140),
		"target_url":  targetURL,
	}
	_, err := g.api(ctx, http.MethodPost, "/repos/"+repo.FullName+"/statuses/"+url.PathEscape(sha), token.AccessToken, body, nil)
	return err
}

// GitAuthHeader uses the documented basic-auth form for an OAuth token.
func (g *GitHub) GitAuthHeader(token Token) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:"+token.AccessToken))
}

// VerifyWebhook checks the HMAC-SHA256 signature GitHub computes over the
// exact delivered body with the per-repository secret.
func (g *GitHub) VerifyWebhook(r *http.Request, body []byte, secret string) error {
	signature := r.Header.Get("X-Hub-Signature-256")
	if !strings.HasPrefix(signature, "sha256=") {
		return fmt.Errorf("missing X-Hub-Signature-256")
	}
	want, err := hex.DecodeString(strings.TrimPrefix(signature, "sha256="))
	if err != nil {
		return fmt.Errorf("malformed signature")
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	if !hmac.Equal(want, mac.Sum(nil)) {
		return fmt.Errorf("signature mismatch")
	}
	return nil
}

func (g *GitHub) ParsePush(body []byte) (Push, error) {
	var out struct {
		Ref        string `json:"ref"`
		Before     string `json:"before"`
		After      string `json:"after"`
		Deleted    bool   `json:"deleted"`
		Repository struct {
			ID            int64  `json:"id"`
			FullName      string `json:"full_name"`
			DefaultBranch string `json:"default_branch"`
		} `json:"repository"`
		HeadCommit *struct {
			Message string `json:"message"`
			Author  struct {
				Name string `json:"name"`
			} `json:"author"`
		} `json:"head_commit"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return Push{}, fmt.Errorf("github: decode push: %w", err)
	}
	p := Push{
		RepoID:     strconv.FormatInt(out.Repository.ID, 10),
		FullName:   out.Repository.FullName,
		Ref:        out.Ref,
		Before:     out.Before,
		After:      out.After,
		Default:    out.Repository.DefaultBranch,
		IsBranch:   strings.HasPrefix(out.Ref, "refs/heads/"),
		IsDeletion: out.Deleted || isZeroCommit(out.After),
	}
	if out.HeadCommit != nil {
		p.Message = out.HeadCommit.Message
		p.Author = out.HeadCommit.Author.Name
	}
	return p, nil
}

// pathEscape keeps the separators of a repository path while escaping each
// segment, so a path can never traverse the API namespace.
func pathEscape(path string) string {
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for i, p := range parts {
		parts[i] = url.PathEscape(p)
	}
	return strings.Join(parts, "/")
}

func isZeroCommit(sha string) bool {
	return sha == "" || strings.Trim(sha, "0") == ""
}

func truncate(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
