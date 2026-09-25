// Package config reads the deployment configuration of the SwiftProof hub.
//
// Everything an operator needs is an environment variable: the same image runs
// on a public deployment and inside a company, pointed at github.com, a GitHub
// Enterprise host or a self-managed GitLab. No configuration file is required
// and no credential is ever read from the analyzed repositories.
package config

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Analysis modes. Lint never executes repository code; review runs the
// configured checks in Docker and therefore needs a Docker socket, which the
// operator must mount deliberately.
const (
	ModeLint   = "lint"
	ModeReview = "review"
)

// Forge identifiers.
const (
	GitHub = "github"
	GitLab = "gitlab"
)

// Provider settings belong to the deployment, exactly as for the CLI: the hub
// holds no API key of its own and only forwards these to the binary it runs.
const (
	EndpointEnvName = "SWIFTPROOF_REVIEWER_ENDPOINT"
	ModelEnvName    = "SWIFTPROOF_REVIEWER_MODEL"
)

// Forge holds the OAuth application and host of one code forge.
type Forge struct {
	Kind         string
	ClientID     string
	ClientSecret string
	// BaseURL serves the OAuth authorize/token endpoints and the web UI.
	BaseURL string
	// APIURL is the REST API root, which differs from BaseURL on github.com.
	APIURL string
	Scopes string
}

// Config is the resolved deployment configuration.
type Config struct {
	Addr    string
	BaseURL string
	DataDir string
	// SessionKey seals session cookies and forge tokens at rest.
	SessionKey []byte
	// Binary is the SwiftProof CLI the analysis runner executes.
	Binary          string
	Mode            string
	Workers         int
	QueueSize       int
	AnalysisTimeout time.Duration
	CloneDepth      int
	MaxRepos        int
	SessionTTL      time.Duration
	// CommitStatus publishes the outcome back onto the analyzed commit.
	CommitStatus bool
	// DefaultBranchOnly restricts push analysis to the default branch.
	DefaultBranchOnly bool
	// Forges is keyed by forge kind and holds only configured forges.
	Forges map[string]Forge
}

// Default values chosen so that a bare `docker run` with one OAuth app works.
const (
	defaultAddr      = ":8080"
	defaultDataDir   = "/var/lib/swiftproof-hub"
	defaultBinary    = "swiftproof"
	defaultWorkers   = 2
	defaultQueue     = 256
	defaultTimeout   = 10 * time.Minute
	defaultDepth     = 50
	defaultMaxRepos  = 500
	defaultSessionMs = 12 * time.Hour
)

// Load resolves the configuration from getenv, creating the data directory and
// a persistent session key when they do not exist yet.
func Load(getenv func(string) string) (Config, error) {
	c := Config{
		Addr:              env(getenv, "SWIFTPROOF_HUB_ADDR", defaultAddr),
		DataDir:           env(getenv, "SWIFTPROOF_HUB_DATA_DIR", defaultDataDir),
		Binary:            env(getenv, "SWIFTPROOF_HUB_BINARY", defaultBinary),
		Mode:              strings.ToLower(env(getenv, "SWIFTPROOF_HUB_MODE", ModeLint)),
		Workers:           envInt(getenv, "SWIFTPROOF_HUB_WORKERS", defaultWorkers),
		QueueSize:         envInt(getenv, "SWIFTPROOF_HUB_QUEUE_SIZE", defaultQueue),
		AnalysisTimeout:   envDuration(getenv, "SWIFTPROOF_HUB_ANALYSIS_TIMEOUT", defaultTimeout),
		CloneDepth:        envInt(getenv, "SWIFTPROOF_HUB_CLONE_DEPTH", defaultDepth),
		MaxRepos:          envInt(getenv, "SWIFTPROOF_HUB_MAX_REPOS", defaultMaxRepos),
		SessionTTL:        envDuration(getenv, "SWIFTPROOF_HUB_SESSION_TTL", defaultSessionMs),
		CommitStatus:      envBool(getenv, "SWIFTPROOF_HUB_COMMIT_STATUS", true),
		DefaultBranchOnly: envBool(getenv, "SWIFTPROOF_HUB_DEFAULT_BRANCH_ONLY", false),
		Forges:            map[string]Forge{},
	}
	base := strings.TrimRight(strings.TrimSpace(getenv("SWIFTPROOF_HUB_BASE_URL")), "/")
	if base == "" {
		return c, fmt.Errorf("SWIFTPROOF_HUB_BASE_URL is required: the forge needs a reachable callback and webhook URL")
	}
	u, err := url.Parse(base)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return c, fmt.Errorf("SWIFTPROOF_HUB_BASE_URL must be an absolute http(s) URL, got %q", base)
	}
	c.BaseURL = base
	if c.Mode != ModeLint && c.Mode != ModeReview {
		return c, fmt.Errorf("SWIFTPROOF_HUB_MODE must be %q or %q, got %q", ModeLint, ModeReview, c.Mode)
	}
	if c.Workers < 1 || c.Workers > 64 {
		return c, fmt.Errorf("SWIFTPROOF_HUB_WORKERS must be between 1 and 64")
	}
	if c.QueueSize < 1 || c.QueueSize > 100000 {
		return c, fmt.Errorf("SWIFTPROOF_HUB_QUEUE_SIZE must be between 1 and 100000")
	}
	if c.CloneDepth < 1 || c.CloneDepth > 10000 {
		return c, fmt.Errorf("SWIFTPROOF_HUB_CLONE_DEPTH must be between 1 and 10000")
	}
	if c.MaxRepos < 1 || c.MaxRepos > 10000 {
		return c, fmt.Errorf("SWIFTPROOF_HUB_MAX_REPOS must be between 1 and 10000")
	}
	if c.AnalysisTimeout < time.Minute || c.AnalysisTimeout > 6*time.Hour {
		return c, fmt.Errorf("SWIFTPROOF_HUB_ANALYSIS_TIMEOUT must be between 1m and 6h")
	}
	if c.SessionTTL < time.Minute || c.SessionTTL > 30*24*time.Hour {
		return c, fmt.Errorf("SWIFTPROOF_HUB_SESSION_TTL must be between 1m and 720h")
	}

	if id := strings.TrimSpace(getenv("SWIFTPROOF_HUB_GITHUB_CLIENT_ID")); id != "" {
		f := Forge{
			Kind:         GitHub,
			ClientID:     id,
			ClientSecret: secret(getenv, "SWIFTPROOF_HUB_GITHUB_CLIENT_SECRET"),
			BaseURL:      strings.TrimRight(env(getenv, "SWIFTPROOF_HUB_GITHUB_URL", "https://github.com"), "/"),
			// A GitHub Enterprise Server host serves its API under /api/v3.
			APIURL: strings.TrimRight(env(getenv, "SWIFTPROOF_HUB_GITHUB_API_URL", "https://api.github.com"), "/"),
			Scopes: env(getenv, "SWIFTPROOF_HUB_GITHUB_SCOPES", "repo,read:org"),
		}
		if f.ClientSecret == "" {
			return c, fmt.Errorf("SWIFTPROOF_HUB_GITHUB_CLIENT_SECRET is required when the GitHub client id is set")
		}
		c.Forges[GitHub] = f
	}
	if id := strings.TrimSpace(getenv("SWIFTPROOF_HUB_GITLAB_CLIENT_ID")); id != "" {
		f := Forge{
			Kind:         GitLab,
			ClientID:     id,
			ClientSecret: secret(getenv, "SWIFTPROOF_HUB_GITLAB_CLIENT_SECRET"),
			BaseURL:      strings.TrimRight(env(getenv, "SWIFTPROOF_HUB_GITLAB_URL", "https://gitlab.com"), "/"),
			Scopes:       env(getenv, "SWIFTPROOF_HUB_GITLAB_SCOPES", "api"),
		}
		f.APIURL = f.BaseURL + "/api/v4"
		if f.ClientSecret == "" {
			return c, fmt.Errorf("SWIFTPROOF_HUB_GITLAB_CLIENT_SECRET is required when the GitLab client id is set")
		}
		c.Forges[GitLab] = f
	}
	// A deployment normally has to name a forge, so a typo in the OAuth
	// variables fails loudly instead of serving an application nobody can sign
	// in to. SWIFTPROOF_HUB_ALLOW_NO_FORGE is the deliberate exception: it lets
	// a public deployment answer on its domain before its OAuth application
	// exists, with a sign-in page that says no forge is configured.
	if len(c.Forges) == 0 && !envBool(getenv, "SWIFTPROOF_HUB_ALLOW_NO_FORGE", false) {
		return c, fmt.Errorf("configure at least one forge: set SWIFTPROOF_HUB_GITHUB_CLIENT_ID or SWIFTPROOF_HUB_GITLAB_CLIENT_ID, or SWIFTPROOF_HUB_ALLOW_NO_FORGE=true to start without sign-in")
	}

	if err := os.MkdirAll(c.DataDir, 0o700); err != nil {
		return c, fmt.Errorf("data directory: %w", err)
	}
	c.SessionKey, err = sessionKey(getenv, c.DataDir)
	if err != nil {
		return c, err
	}
	return c, nil
}

// CallbackURL is the OAuth redirect registered in the forge application.
func (c Config) CallbackURL(kind string) string {
	return c.BaseURL + "/auth/" + kind + "/callback"
}

// WebhookURL is the push endpoint a repository hook posts to. The routing key
// is random per repository, so the URL is not enumerable.
func (c Config) WebhookURL(hookKey string) string {
	return c.BaseURL + "/hooks/" + hookKey
}

// sessionKey prefers an operator-provided key so that several replicas share
// sessions; otherwise it persists a generated one next to the data.
func sessionKey(getenv func(string) string, dir string) ([]byte, error) {
	if raw := strings.TrimSpace(getenv("SWIFTPROOF_HUB_SESSION_KEY")); raw != "" {
		key, err := hex.DecodeString(raw)
		if err != nil || len(key) != 32 {
			return nil, fmt.Errorf("SWIFTPROOF_HUB_SESSION_KEY must be 64 hex characters (32 bytes)")
		}
		return key, nil
	}
	path := filepath.Join(dir, "session.key")
	if data, err := os.ReadFile(path); err == nil {
		key, decodeErr := hex.DecodeString(strings.TrimSpace(string(data)))
		if decodeErr == nil && len(key) == 32 {
			return key, nil
		}
		return nil, fmt.Errorf("%s is corrupt: remove it to rotate the key", path)
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("session key: %w", err)
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("session key: %w", err)
	}
	if err := os.WriteFile(path, []byte(hex.EncodeToString(key)+"\n"), 0o600); err != nil {
		return nil, fmt.Errorf("session key: %w", err)
	}
	return key, nil
}

// secret reads a value directly or, following the Docker secret convention the
// CLI already uses, from the file named by <NAME>_FILE.
func secret(getenv func(string) string, name string) string {
	if path := strings.TrimSpace(getenv(name + "_FILE")); path != "" {
		data, err := os.ReadFile(path)
		if err == nil {
			return strings.TrimSpace(string(data))
		}
	}
	if data, err := os.ReadFile(filepath.Join("/run/secrets", name)); err == nil {
		return strings.TrimSpace(string(data))
	}
	return strings.TrimSpace(getenv(name))
}

func env(getenv func(string) string, name, fallback string) string {
	if v := strings.TrimSpace(getenv(name)); v != "" {
		return v
	}
	return fallback
}

func envInt(getenv func(string) string, name string, fallback int) int {
	v, err := strconv.Atoi(env(getenv, name, ""))
	if err != nil {
		return fallback
	}
	return v
}

func envBool(getenv func(string) string, name string, fallback bool) bool {
	v, err := strconv.ParseBool(env(getenv, name, ""))
	if err != nil {
		return fallback
	}
	return v
}

func envDuration(getenv func(string) string, name string, fallback time.Duration) time.Duration {
	v, err := time.ParseDuration(env(getenv, name, ""))
	if err != nil {
		return fallback
	}
	return v
}
