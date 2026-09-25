// Package forge talks to the code hosts the hub supports.
//
// Both providers expose the same small surface: authenticate a user, list the
// repositories they can administer, read and create the `.swiftproof.json`
// policy on the default branch, install a push webhook, and publish a commit
// status. Everything else the hub does is local.
package forge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// PolicyPath is the file the hub creates and watches for.
const PolicyPath = ".swiftproof.json"

// StatusContext labels the commit status the hub publishes.
const StatusContext = "swiftproof"

// Commit status states, mapped per provider.
const (
	StatePending = "pending"
	StateSuccess = "success"
	StateFailure = "failure"
	StateError   = "error"
)

// Token is an OAuth credential. Refresh and Expiry are only set by providers
// that issue expiring tokens.
type Token struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	Expiry       time.Time `json:"expiry,omitempty"`
}

// Expired reports whether the token needs refreshing, with a safety margin.
func (t Token) Expired(now time.Time) bool {
	return !t.Expiry.IsZero() && now.Add(time.Minute).After(t.Expiry)
}

// User is the authenticated forge account.
type User struct {
	ID        string
	Login     string
	Name      string
	AvatarURL string
	WebURL    string
}

// Repo is a repository the user can act on.
type Repo struct {
	ID            string
	FullName      string
	WebURL        string
	CloneURL      string
	DefaultBranch string
	Private       bool
	// Admin reports whether the user may install a webhook on this repository.
	Admin bool
}

// Commit is the tip of a branch.
type Commit struct {
	SHA     string
	Message string
	Author  string
}

// Push is a normalized push event.
type Push struct {
	RepoID     string
	FullName   string
	Ref        string
	Before     string
	After      string
	Message    string
	Author     string
	Default    string
	IsBranch   bool
	IsDeletion bool
}

// Provider is one code host.
type Provider interface {
	Kind() string
	// AuthURL starts the OAuth flow.
	AuthURL(state, redirect string) string
	Exchange(ctx context.Context, code, redirect string) (Token, error)
	Refresh(ctx context.Context, token Token) (Token, error)
	CurrentUser(ctx context.Context, token Token) (User, error)
	ListRepos(ctx context.Context, token Token, max int) ([]Repo, error)
	// ReadFile returns the file at ref; found is false on 404.
	ReadFile(ctx context.Context, token Token, repo Repo, ref, path string) (content []byte, found bool, err error)
	CreateFile(ctx context.Context, token Token, repo Repo, branch, path, message string, content []byte) error
	ListRoot(ctx context.Context, token Token, repo Repo, ref string) ([]string, error)
	// HeadCommit resolves a branch to its tip, so the hub can analyze a
	// repository on demand without waiting for the next push.
	HeadCommit(ctx context.Context, token Token, repo Repo, ref string) (Commit, error)
	CreateHook(ctx context.Context, token Token, repo Repo, target, secret string) (string, error)
	DeleteHook(ctx context.Context, token Token, repo Repo, id string) error
	SetStatus(ctx context.Context, token Token, repo Repo, sha, state, description, targetURL string) error
	// GitAuthHeader is the HTTP Authorization header value used to fetch the
	// repository. It is passed to git through the environment, never on argv.
	GitAuthHeader(token Token) string
	// VerifyWebhook authenticates a delivery against the per-repository secret.
	VerifyWebhook(r *http.Request, body []byte, secret string) error
	ParsePush(body []byte) (Push, error)
}

// Error carries the HTTP status of a failed forge call, so callers can tell a
// permission problem from a missing resource.
type Error struct {
	Status int
	Op     string
	Detail string
}

func (e *Error) Error() string {
	if e.Detail == "" {
		return fmt.Sprintf("%s: forge returned %d", e.Op, e.Status)
	}
	return fmt.Sprintf("%s: forge returned %d: %s", e.Op, e.Status, e.Detail)
}

// StatusOf returns the HTTP status behind an error, or 0.
func StatusOf(err error) int {
	var fe *Error
	if errors.As(err, &fe) {
		return fe.Status
	}
	return 0
}

// maxResponseBytes bounds any forge response the hub reads into memory.
const maxResponseBytes = 8 << 20

// client is the shared HTTP plumbing: bounded reads, no credential in errors,
// and redirects confined to the configured host.
type client struct {
	http *http.Client
}

func newClient() *client {
	return &client{http: &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return fmt.Errorf("too many redirects")
			}
			if req.URL.Host != via[0].URL.Host {
				return fmt.Errorf("refusing cross-host redirect to %s", req.URL.Host)
			}
			return nil
		},
	}}
}

type request struct {
	method  string
	url     string
	token   string
	accept  string
	body    io.Reader
	ctype   string
	headers map[string]string
}

// do executes a request and decodes a JSON response into out when it is not
// nil. It never puts the credential into the returned error.
func (c *client) do(ctx context.Context, r request, out any) (int, error) {
	req, err := http.NewRequestWithContext(ctx, r.method, r.url, r.body)
	if err != nil {
		return 0, fmt.Errorf("%s %s: %w", r.method, redact(r.url), err)
	}
	req.Header.Set("User-Agent", "swiftproof-hub")
	if r.accept != "" {
		req.Header.Set("Accept", r.accept)
	}
	if r.ctype != "" {
		req.Header.Set("Content-Type", r.ctype)
	}
	if r.token != "" {
		req.Header.Set("Authorization", "Bearer "+r.token)
	}
	for k, v := range r.headers {
		req.Header.Set(k, v)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, fmt.Errorf("%s %s: %w", r.method, redact(r.url), err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return resp.StatusCode, fmt.Errorf("%s %s: %w", r.method, redact(r.url), err)
	}
	if resp.StatusCode >= 400 {
		return resp.StatusCode, &Error{Status: resp.StatusCode, Op: r.method + " " + redact(r.url), Detail: snippet(data)}
	}
	if out != nil && len(data) > 0 {
		if err := json.Unmarshal(data, out); err != nil {
			return resp.StatusCode, fmt.Errorf("%s %s: decode response: %w", r.method, redact(r.url), err)
		}
	}
	return resp.StatusCode, nil
}

// redact removes any query string from a URL before it reaches a log or an
// error: OAuth endpoints carry the code and the client secret there.
func redact(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "[url]"
	}
	u.RawQuery = ""
	u.User = nil
	return u.String()
}

// snippet bounds a provider error message so a response cannot flood the logs.
func snippet(data []byte) string {
	text := strings.TrimSpace(string(data))
	text = strings.Join(strings.Fields(text), " ")
	if len(text) > 300 {
		text = text[:300] + "…"
	}
	return text
}

func form(values url.Values) io.Reader { return strings.NewReader(values.Encode()) }

// jsonBody encodes a request payload.
func jsonBody(value any) (io.Reader, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return strings.NewReader(string(data)), nil
}

// DetectLanguage maps a repository root listing onto a SwiftProof language.
// The CLI does the same from a working tree; here only the forge listing is
// available, so the markers are matched by name.
func DetectLanguage(entries []string) string {
	has := func(name string) bool {
		for _, e := range entries {
			if strings.EqualFold(e, name) {
				return true
			}
		}
		return false
	}
	switch {
	case has("go.mod"), has("go.work"):
		return "go"
	case has("tsconfig.json"):
		return "typescript"
	case has("package.json"):
		return "javascript"
	case has("pyproject.toml"), has("setup.py"), has("requirements.txt"):
		return "python"
	default:
		return "unknown"
	}
}
