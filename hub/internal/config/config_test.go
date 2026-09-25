package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func envOf(values map[string]string) func(string) string {
	return func(name string) string { return values[name] }
}

func baseEnv(dir string) map[string]string {
	return map[string]string{
		"SWIFTPROOF_HUB_BASE_URL":             "https://swiftproof.example.com",
		"SWIFTPROOF_HUB_DATA_DIR":             dir,
		"SWIFTPROOF_HUB_GITHUB_CLIENT_ID":     "id",
		"SWIFTPROOF_HUB_GITHUB_CLIENT_SECRET": "secret",
	}
}

func TestLoadDefaults(t *testing.T) {
	dir := t.TempDir()
	c, err := Load(envOf(baseEnv(dir)))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Addr != ":8080" || c.Mode != ModeLint || c.Workers != 2 {
		t.Errorf("defaults = %+v", c)
	}
	if !c.CommitStatus || c.DefaultBranchOnly {
		t.Errorf("commit status defaults on, default-branch-only defaults off; got %v, %v", c.CommitStatus, c.DefaultBranchOnly)
	}
	if len(c.SessionKey) != 32 {
		t.Fatalf("session key length = %d, want 32", len(c.SessionKey))
	}
	if c.CallbackURL(GitHub) != "https://swiftproof.example.com/auth/github/callback" {
		t.Errorf("CallbackURL = %q", c.CallbackURL(GitHub))
	}
	if c.WebhookURL("abc") != "https://swiftproof.example.com/hooks/abc" {
		t.Errorf("WebhookURL = %q", c.WebhookURL("abc"))
	}
	gh := c.Forges[GitHub]
	if gh.APIURL != "https://api.github.com" || gh.BaseURL != "https://github.com" {
		t.Errorf("github hosts = %+v", gh)
	}
}

func TestSessionKeyIsPersistedAndReused(t *testing.T) {
	dir := t.TempDir()
	first, err := Load(envOf(baseEnv(dir)))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	info, err := os.Stat(filepath.Join(dir, "session.key"))
	if err != nil {
		t.Fatalf("the generated key must be persisted: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("session key mode = %o, want 600", mode)
	}
	second, err := Load(envOf(baseEnv(dir)))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if string(first.SessionKey) != string(second.SessionKey) {
		t.Fatal("restarting must not invalidate the sessions of the users")
	}
}

func TestSessionKeyFromTheEnvironmentIsValidated(t *testing.T) {
	dir := t.TempDir()
	values := baseEnv(dir)
	values["SWIFTPROOF_HUB_SESSION_KEY"] = strings.Repeat("ab", 32)
	c, err := Load(envOf(values))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(c.SessionKey) != 32 || c.SessionKey[0] != 0xab {
		t.Errorf("session key = %x", c.SessionKey)
	}
	if _, err := os.Stat(filepath.Join(dir, "session.key")); !os.IsNotExist(err) {
		t.Error("an operator-provided key must not be written to disk")
	}
	values["SWIFTPROOF_HUB_SESSION_KEY"] = "too-short"
	if _, err := Load(envOf(values)); err == nil {
		t.Fatal("a malformed key must be refused")
	}
}

func TestLoadRefusesAnIncompleteDeployment(t *testing.T) {
	dir := t.TempDir()
	cases := map[string]map[string]string{
		"no base url": {"SWIFTPROOF_HUB_GITHUB_CLIENT_ID": "id", "SWIFTPROOF_HUB_GITHUB_CLIENT_SECRET": "s"},
		"relative base url": {
			"SWIFTPROOF_HUB_BASE_URL": "swiftproof.example.com", "SWIFTPROOF_HUB_DATA_DIR": dir,
			"SWIFTPROOF_HUB_GITHUB_CLIENT_ID": "id", "SWIFTPROOF_HUB_GITHUB_CLIENT_SECRET": "s",
		},
		"no forge": {"SWIFTPROOF_HUB_BASE_URL": "https://x.example", "SWIFTPROOF_HUB_DATA_DIR": dir},
		"github without secret": {
			"SWIFTPROOF_HUB_BASE_URL": "https://x.example", "SWIFTPROOF_HUB_DATA_DIR": dir,
			"SWIFTPROOF_HUB_GITHUB_CLIENT_ID": "id",
		},
	}
	for name, values := range cases {
		if _, err := Load(envOf(values)); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestLoadValidatesBounds(t *testing.T) {
	dir := t.TempDir()
	for name, override := range map[string]map[string]string{
		"mode":     {"SWIFTPROOF_HUB_MODE": "audit"},
		"workers":  {"SWIFTPROOF_HUB_WORKERS": "0"},
		"depth":    {"SWIFTPROOF_HUB_CLONE_DEPTH": "-1"},
		"timeout":  {"SWIFTPROOF_HUB_ANALYSIS_TIMEOUT": "1s"},
		"sessions": {"SWIFTPROOF_HUB_SESSION_TTL": "10000h"},
	} {
		values := baseEnv(dir)
		for k, v := range override {
			values[k] = v
		}
		if _, err := Load(envOf(values)); err == nil {
			t.Errorf("%s: an out-of-range value must be refused", name)
		}
	}
}

func TestSelfManagedHosts(t *testing.T) {
	dir := t.TempDir()
	values := map[string]string{
		"SWIFTPROOF_HUB_BASE_URL":             "http://hub.internal:8080",
		"SWIFTPROOF_HUB_DATA_DIR":             dir,
		"SWIFTPROOF_HUB_GITHUB_CLIENT_ID":     "id",
		"SWIFTPROOF_HUB_GITHUB_CLIENT_SECRET": "s",
		"SWIFTPROOF_HUB_GITHUB_URL":           "https://ghe.internal/",
		"SWIFTPROOF_HUB_GITHUB_API_URL":       "https://ghe.internal/api/v3/",
		"SWIFTPROOF_HUB_GITLAB_CLIENT_ID":     "gid",
		"SWIFTPROOF_HUB_GITLAB_CLIENT_SECRET": "gs",
		"SWIFTPROOF_HUB_GITLAB_URL":           "https://gitlab.internal",
		"SWIFTPROOF_HUB_MODE":                 "review",
		"SWIFTPROOF_HUB_DEFAULT_BRANCH_ONLY":  "true",
		"SWIFTPROOF_HUB_ANALYSIS_TIMEOUT":     "30m",
	}
	c, err := Load(envOf(values))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(c.Forges) != 2 {
		t.Fatalf("both forges must be configured, got %d", len(c.Forges))
	}
	if c.Forges[GitHub].APIURL != "https://ghe.internal/api/v3" {
		t.Errorf("trailing slashes must be trimmed, got %q", c.Forges[GitHub].APIURL)
	}
	if c.Forges[GitLab].APIURL != "https://gitlab.internal/api/v4" {
		t.Errorf("gitlab api = %q", c.Forges[GitLab].APIURL)
	}
	if c.Mode != ModeReview || !c.DefaultBranchOnly || c.AnalysisTimeout != 30*time.Minute {
		t.Errorf("overrides = %+v", c)
	}
}

func TestSecretCanComeFromAFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "client_secret")
	if err := os.WriteFile(path, []byte("file-secret\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	values := baseEnv(dir)
	delete(values, "SWIFTPROOF_HUB_GITHUB_CLIENT_SECRET")
	values["SWIFTPROOF_HUB_GITHUB_CLIENT_SECRET_FILE"] = path
	c, err := Load(envOf(values))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Forges[GitHub].ClientSecret != "file-secret" {
		t.Errorf("secret = %q, want the trimmed file content", c.Forges[GitHub].ClientSecret)
	}
}
