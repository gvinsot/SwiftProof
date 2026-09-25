package forge

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gvinsot/SwiftProof/hub/internal/config"
)

// GitLab speaks API v4, on gitlab.com or on a self-managed instance.
type GitLab struct {
	cfg    config.Forge
	client *client
}

// NewGitLab builds the GitLab provider.
func NewGitLab(cfg config.Forge) *GitLab { return &GitLab{cfg: cfg, client: newClient()} }

func (g *GitLab) Kind() string { return config.GitLab }

func (g *GitLab) AuthURL(state, redirect string) string {
	q := url.Values{
		"client_id":     {g.cfg.ClientID},
		"redirect_uri":  {redirect},
		"response_type": {"code"},
		"scope":         {strings.ReplaceAll(g.cfg.Scopes, ",", " ")},
		"state":         {state},
	}
	return g.cfg.BaseURL + "/oauth/authorize?" + q.Encode()
}

func (g *GitLab) Exchange(ctx context.Context, code, redirect string) (Token, error) {
	return g.token(ctx, url.Values{
		"client_id":     {g.cfg.ClientID},
		"client_secret": {g.cfg.ClientSecret},
		"code":          {code},
		"grant_type":    {"authorization_code"},
		"redirect_uri":  {redirect},
	})
}

// Refresh renews the short-lived access token GitLab issues by default.
func (g *GitLab) Refresh(ctx context.Context, token Token) (Token, error) {
	if token.RefreshToken == "" {
		return token, fmt.Errorf("gitlab: no refresh token")
	}
	return g.token(ctx, url.Values{
		"client_id":     {g.cfg.ClientID},
		"client_secret": {g.cfg.ClientSecret},
		"refresh_token": {token.RefreshToken},
		"grant_type":    {"refresh_token"},
	})
}

func (g *GitLab) token(ctx context.Context, values url.Values) (Token, error) {
	var out struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in"`
		Error        string `json:"error"`
	}
	_, err := g.client.do(ctx, request{
		method: http.MethodPost,
		url:    g.cfg.BaseURL + "/oauth/token",
		accept: "application/json",
		ctype:  "application/x-www-form-urlencoded",
		body:   form(values),
	}, &out)
	if err != nil {
		return Token{}, err
	}
	if out.AccessToken == "" {
		return Token{}, fmt.Errorf("gitlab: authorization failed (%s)", out.Error)
	}
	t := Token{AccessToken: out.AccessToken, RefreshToken: out.RefreshToken}
	if out.ExpiresIn > 0 {
		t.Expiry = time.Now().Add(time.Duration(out.ExpiresIn) * time.Second)
	}
	return t, nil
}

func (g *GitLab) api(ctx context.Context, method, path, token string, body any, out any) (int, error) {
	r := request{method: method, url: g.cfg.APIURL + path, token: token, accept: "application/json"}
	if body != nil {
		encoded, err := jsonBody(body)
		if err != nil {
			return 0, err
		}
		r.body, r.ctype = encoded, "application/json"
	}
	return g.client.do(ctx, r, out)
}

func (g *GitLab) CurrentUser(ctx context.Context, token Token) (User, error) {
	var out struct {
		ID        int64  `json:"id"`
		Username  string `json:"username"`
		Name      string `json:"name"`
		AvatarURL string `json:"avatar_url"`
		WebURL    string `json:"web_url"`
	}
	if _, err := g.api(ctx, http.MethodGet, "/user", token.AccessToken, nil, &out); err != nil {
		return User{}, err
	}
	return User{ID: strconv.FormatInt(out.ID, 10), Login: out.Username, Name: out.Name, AvatarURL: out.AvatarURL, WebURL: out.WebURL}, nil
}

type gitlabProject struct {
	ID                int64  `json:"id"`
	PathWithNamespace string `json:"path_with_namespace"`
	WebURL            string `json:"web_url"`
	HTTPURLToRepo     string `json:"http_url_to_repo"`
	DefaultBranch     string `json:"default_branch"`
	Visibility        string `json:"visibility"`
	Archived          bool   `json:"archived"`
	Permissions       struct {
		ProjectAccess *struct {
			AccessLevel int `json:"access_level"`
		} `json:"project_access"`
		GroupAccess *struct {
			AccessLevel int `json:"access_level"`
		} `json:"group_access"`
	} `json:"permissions"`
}

// maintainerLevel is the access level GitLab requires to manage project hooks.
const maintainerLevel = 40

func (g *GitLab) ListRepos(ctx context.Context, token Token, max int) ([]Repo, error) {
	repos := make([]Repo, 0, 64)
	for page := 1; page <= 20 && len(repos) < max; page++ {
		var out []gitlabProject
		path := fmt.Sprintf("/projects?membership=true&per_page=100&page=%d&order_by=last_activity_at&min_access_level=30&archived=false", page)
		if _, err := g.api(ctx, http.MethodGet, path, token.AccessToken, nil, &out); err != nil {
			return nil, err
		}
		for _, p := range out {
			if p.Archived {
				continue
			}
			level := 0
			if p.Permissions.ProjectAccess != nil {
				level = p.Permissions.ProjectAccess.AccessLevel
			}
			if p.Permissions.GroupAccess != nil && p.Permissions.GroupAccess.AccessLevel > level {
				level = p.Permissions.GroupAccess.AccessLevel
			}
			repos = append(repos, Repo{
				ID:            strconv.FormatInt(p.ID, 10),
				FullName:      p.PathWithNamespace,
				WebURL:        p.WebURL,
				CloneURL:      p.HTTPURLToRepo,
				DefaultBranch: p.DefaultBranch,
				Private:       p.Visibility != "public",
				Admin:         level >= maintainerLevel,
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

// project builds the /projects/:id prefix; the numeric id avoids escaping the
// namespace path on every call.
func (g *GitLab) project(repo Repo) string { return "/projects/" + url.PathEscape(repo.ID) }

func (g *GitLab) ReadFile(ctx context.Context, token Token, repo Repo, ref, path string) ([]byte, bool, error) {
	var out struct {
		Content  string `json:"content"`
		Encoding string `json:"encoding"`
	}
	target := g.project(repo) + "/repository/files/" + url.PathEscape(strings.TrimPrefix(path, "/")) + "?ref=" + url.QueryEscape(ref)
	status, err := g.api(ctx, http.MethodGet, target, token.AccessToken, nil, &out)
	if status == http.StatusNotFound {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if out.Encoding != "base64" {
		return []byte(out.Content), true, nil
	}
	data, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(out.Content, "\n", ""))
	if err != nil {
		return nil, true, fmt.Errorf("gitlab: decode %s: %w", path, err)
	}
	return data, true, nil
}

func (g *GitLab) CreateFile(ctx context.Context, token Token, repo Repo, branch, path, message string, content []byte) error {
	body := map[string]any{
		"branch":         branch,
		"content":        base64.StdEncoding.EncodeToString(content),
		"encoding":       "base64",
		"commit_message": message,
	}
	target := g.project(repo) + "/repository/files/" + url.PathEscape(strings.TrimPrefix(path, "/"))
	_, err := g.api(ctx, http.MethodPost, target, token.AccessToken, body, nil)
	return err
}

func (g *GitLab) ListRoot(ctx context.Context, token Token, repo Repo, ref string) ([]string, error) {
	var out []struct {
		Name string `json:"name"`
	}
	target := g.project(repo) + "/repository/tree?per_page=100&ref=" + url.QueryEscape(ref)
	if _, err := g.api(ctx, http.MethodGet, target, token.AccessToken, nil, &out); err != nil {
		return nil, err
	}
	names := make([]string, 0, len(out))
	for _, e := range out {
		names = append(names, e.Name)
	}
	return names, nil
}

func (g *GitLab) HeadCommit(ctx context.Context, token Token, repo Repo, ref string) (Commit, error) {
	var out struct {
		ID         string `json:"id"`
		Message    string `json:"message"`
		AuthorName string `json:"author_name"`
	}
	target := g.project(repo) + "/repository/commits/" + url.PathEscape(ref)
	if _, err := g.api(ctx, http.MethodGet, target, token.AccessToken, nil, &out); err != nil {
		return Commit{}, err
	}
	if out.ID == "" {
		return Commit{}, fmt.Errorf("gitlab: %s has no commit on %s", repo.FullName, ref)
	}
	return Commit{SHA: out.ID, Message: out.Message, Author: out.AuthorName}, nil
}

func (g *GitLab) CreateHook(ctx context.Context, token Token, repo Repo, target, secret string) (string, error) {
	body := map[string]any{
		"url":                       target,
		"push_events":               true,
		"token":                     secret,
		"enable_ssl_verification":   strings.HasPrefix(target, "https://"),
		"merge_requests_events":     false,
		"issues_events":             false,
		"pipeline_events":           false,
		"push_events_branch_filter": "",
	}
	var out struct {
		ID int64 `json:"id"`
	}
	if _, err := g.api(ctx, http.MethodPost, g.project(repo)+"/hooks", token.AccessToken, body, &out); err != nil {
		return "", err
	}
	return strconv.FormatInt(out.ID, 10), nil
}

func (g *GitLab) DeleteHook(ctx context.Context, token Token, repo Repo, id string) error {
	if id == "" {
		return nil
	}
	status, err := g.api(ctx, http.MethodDelete, g.project(repo)+"/hooks/"+url.PathEscape(id), token.AccessToken, nil, nil)
	if status == http.StatusNotFound {
		return nil
	}
	return err
}

// SetStatus maps the shared states onto the GitLab commit status vocabulary.
func (g *GitLab) SetStatus(ctx context.Context, token Token, repo Repo, sha, state, description, targetURL string) error {
	switch state {
	case StateFailure, StateError:
		state = "failed"
	case StatePending:
		state = "running"
	}
	body := map[string]string{
		"state":       state,
		"name":        StatusContext,
		"description": truncate(description, 140),
		"target_url":  targetURL,
	}
	_, err := g.api(ctx, http.MethodPost, g.project(repo)+"/statuses/"+url.PathEscape(sha), token.AccessToken, body, nil)
	return err
}

// GitAuthHeader uses the oauth2 basic-auth form GitLab documents for HTTPS
// clones with an OAuth token.
func (g *GitLab) GitAuthHeader(token Token) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte("oauth2:"+token.AccessToken))
}

// VerifyWebhook compares the per-repository token GitLab echoes back. The
// comparison is constant time so a wrong token leaks nothing.
func (g *GitLab) VerifyWebhook(r *http.Request, _ []byte, secret string) error {
	got := r.Header.Get("X-Gitlab-Token")
	if got == "" {
		return fmt.Errorf("missing X-Gitlab-Token")
	}
	if subtle.ConstantTimeCompare([]byte(got), []byte(secret)) != 1 {
		return fmt.Errorf("token mismatch")
	}
	return nil
}

func (g *GitLab) ParsePush(body []byte) (Push, error) {
	var out struct {
		ObjectKind string `json:"object_kind"`
		Before     string `json:"before"`
		After      string `json:"after"`
		Ref        string `json:"ref"`
		UserName   string `json:"user_name"`
		Project    struct {
			ID                int64  `json:"id"`
			PathWithNamespace string `json:"path_with_namespace"`
			DefaultBranch     string `json:"default_branch"`
		} `json:"project"`
		Commits []struct {
			ID      string `json:"id"`
			Message string `json:"message"`
			Author  struct {
				Name string `json:"name"`
			} `json:"author"`
		} `json:"commits"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return Push{}, fmt.Errorf("gitlab: decode push: %w", err)
	}
	p := Push{
		RepoID:     strconv.FormatInt(out.Project.ID, 10),
		FullName:   out.Project.PathWithNamespace,
		Ref:        out.Ref,
		Before:     out.Before,
		After:      out.After,
		Author:     out.UserName,
		Default:    out.Project.DefaultBranch,
		IsBranch:   strings.HasPrefix(out.Ref, "refs/heads/"),
		IsDeletion: isZeroCommit(out.After),
	}
	// GitLab lists the pushed commits oldest first; the head commit is last.
	for i := len(out.Commits) - 1; i >= 0; i-- {
		if out.Commits[i].ID == out.After {
			p.Message = out.Commits[i].Message
			if out.Commits[i].Author.Name != "" {
				p.Author = out.Commits[i].Author.Name
			}
			break
		}
	}
	return p, nil
}
