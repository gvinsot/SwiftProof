// Package config loads the trusted, versioned review policy.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"strings"

	"github.com/gvinsot/SwiftProof/internal/coverage"
)

const Filename = ".swiftproof.json"

type Sandbox struct {
	Image             string `json:"image"`
	Network           bool   `json:"network"`
	TimeoutSeconds    int    `json:"timeout_seconds"`
	MaxRuntimeSeconds int    `json:"max_runtime_seconds"`
	MaxOutputBytes    int    `json:"max_output_bytes"`
	MemoryMB          int    `json:"memory_mb"`
	CPUs              int    `json:"cpus"`
}

// The provider belongs to the deployment, not to the reviewed repository: one
// image and one committed policy are pointed at the operator's endpoint and
// model through these variables, and at its credential through a Docker
// secret. Everything else — image, commands, budgets, sensitive paths — stays
// a decision of the trusted baseline policy. Neither name ends in a suffix the
// Swarm deployment treats as sensitive, so both stay plain variables.
const (
	EndpointEnv = "SWIFTPROOF_REVIEWER_ENDPOINT"
	ModelEnv    = "SWIFTPROOF_REVIEWER_MODEL"
)

// The credential follows the cluster's secret convention: the deployment turns
// a variable whose name ends in _KEY (here reviewer.api_key_env, by default
// SWIFTPROOF_API_KEY) into a Docker secret, drops it from the container
// environment and mounts its value at /run/secrets/<NAME>. <NAME>_FILE names
// that file explicitly when it is mounted under a different target.
const (
	SecretsDir    = "/run/secrets"
	FileEnvSuffix = "_FILE"
)

type Reviewer struct {
	Endpoint          string `json:"endpoint"`
	Model             string `json:"model"`
	APIKeyEnv         string `json:"api_key_env"`
	MaxIterations     int    `json:"max_iterations"`
	MaxGeneratedTests int    `json:"max_generated_tests"`
	TimeoutSeconds    int    `json:"timeout_seconds"`
	MaxInputBytes     int    `json:"max_input_bytes"`
}

type Config struct {
	Version        int                 `json:"version"`
	Language       string              `json:"language"`
	Commands       map[string][]string `json:"commands"`
	Sandbox        Sandbox             `json:"sandbox"`
	Reviewer       Reviewer            `json:"reviewer"`
	SensitivePaths []string            `json:"sensitive_paths"`
}

func Default(language string) Config {
	c := Config{
		Version: 1, Language: language, Commands: map[string][]string{},
		Sandbox:        Sandbox{Image: "golang:1.26-bookworm", TimeoutSeconds: 120, MaxRuntimeSeconds: 600, MaxOutputBytes: 65536, MemoryMB: 1024, CPUs: 2},
		Reviewer:       Reviewer{Endpoint: "https://api.openai.com/v1/chat/completions", APIKeyEnv: "SWIFTPROOF_API_KEY", MaxIterations: 20, MaxGeneratedTests: 10, TimeoutSeconds: 600, MaxInputBytes: 131072},
		SensitivePaths: []string{"**/auth/**", "**/payment*/**", "**/migrations/**", ".github/workflows/**", ".swiftproof.json"},
	}
	switch language {
	case "go":
		// Coverage is Go-only: the stock Node and Python images ship no coverage
		// tool, so a seeded default there would exit 127 and force exit 4.
		c.Commands = map[string][]string{"test": {"go", "test", "./..."}, "typecheck": {"go", "vet", "./..."}, "build": {"go", "build", "./..."}, "generated_test": {"go", "test", "{package}"}, coverage.CommandKey: {"go", "test", "-covermode=count", "-coverprofile=" + coverage.Placeholder, "./..."}}
	case "typescript", "javascript":
		c.Sandbox.Image = "node:22-bookworm"
		c.Commands = map[string][]string{"test": {"npm", "test"}, "build": {"npm", "run", "build"}}
	case "python":
		c.Sandbox.Image = "python:3.13-bookworm"
		c.Commands = map[string][]string{"test": {"python", "-m", "unittest", "discover"}, "generated_test": {"python", "-m", "unittest", "{file}"}}
	default:
		c.Language = "unknown"
	}
	return c
}

func Decode(data []byte) (Config, error) {
	if len(data) > 1<<20 {
		return Config{}, fmt.Errorf("configuration exceeds 1 MiB")
	}
	if err := validateJSONPolicy(data); err != nil {
		return Config{}, err
	}
	c := Default("unknown")
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&c); err != nil {
		return c, fmt.Errorf("configuration: %w", err)
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return c, fmt.Errorf("configuration must contain exactly one JSON object")
	}
	return c, c.Validate()
}

// A policy must have one unambiguous interpretation. encoding/json otherwise
// silently accepts null at the root and lets later duplicate keys win.
func validateJSONPolicy(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return fmt.Errorf("configuration must be a JSON object")
	}
	d := json.NewDecoder(bytes.NewReader(trimmed))
	d.UseNumber()
	var value func(int) error
	value = func(depth int) error {
		if depth > 64 {
			return fmt.Errorf("configuration nesting exceeds 64 levels")
		}
		token, err := d.Token()
		if err != nil {
			return fmt.Errorf("configuration: %w", err)
		}
		delim, container := token.(json.Delim)
		if !container {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				keyToken, err := d.Token()
				if err != nil {
					return fmt.Errorf("configuration: %w", err)
				}
				key, ok := keyToken.(string)
				if !ok {
					return fmt.Errorf("configuration object keys must be strings")
				}
				folded := strings.ToLower(key)
				if seen[folded] {
					return fmt.Errorf("duplicate configuration key %q", key)
				}
				seen[folded] = true
				if err := value(depth + 1); err != nil {
					return err
				}
			}
		case '[':
			for d.More() {
				if err := value(depth + 1); err != nil {
					return err
				}
			}
		default:
			return fmt.Errorf("unexpected configuration delimiter")
		}
		if _, err := d.Token(); err != nil {
			return fmt.Errorf("configuration: %w", err)
		}
		return nil
	}
	return value(0)
}

func (c Config) Validate() error {
	if c.Version != 1 {
		return fmt.Errorf("unsupported configuration version %d", c.Version)
	}
	for name, argv := range c.Commands {
		if name != "test" && name != "typecheck" && name != "build" && name != "generated_test" && name != coverage.CommandKey {
			return fmt.Errorf("unknown command %q", name)
		}
		if len(argv) == 0 || strings.TrimSpace(argv[0]) == "" || len(argv) > 128 {
			return fmt.Errorf("command %s must be a nonempty argv array (at most 128 arguments)", name)
		}
		placeholders := 0
		for _, arg := range argv {
			if strings.ContainsRune(arg, 0) || len(arg) > 16384 {
				return fmt.Errorf("invalid argument in command %s", name)
			}
			placeholders += strings.Count(arg, coverage.Placeholder)
		}
		// The executed argv is the reviewed argv: SwiftProof expands the token
		// the operator wrote and never appends a coverage flag of its own.
		if name == coverage.CommandKey && placeholders != 1 {
			return fmt.Errorf("command %s must write its profile to %s", coverage.CommandKey, coverage.Placeholder)
		}
	}
	s := c.Sandbox
	if s.Image == "" || strings.HasPrefix(s.Image, "-") || strings.ContainsAny(s.Image, " \t\r\n\x00") {
		return fmt.Errorf("sandbox.image must name a preloaded Docker image")
	}
	if s.TimeoutSeconds < 1 || s.TimeoutSeconds > 3600 || s.MaxRuntimeSeconds < 1 || s.MaxRuntimeSeconds > 7200 {
		return fmt.Errorf("sandbox time limits must be positive and at most 3600/7200 seconds")
	}
	if s.MaxOutputBytes < 1024 || s.MaxOutputBytes > 4<<20 {
		return fmt.Errorf("sandbox.max_output_bytes must be between 1024 and 4194304")
	}
	if s.MemoryMB < 128 || s.MemoryMB > 32768 || s.CPUs < 1 || s.CPUs > 32 {
		return fmt.Errorf("sandbox resources must be 128..32768 MiB and 1..32 CPUs")
	}
	r := c.Reviewer
	if r.MaxIterations < 1 || r.MaxIterations > 100 || r.MaxGeneratedTests < 0 || r.MaxGeneratedTests > 100 {
		return fmt.Errorf("reviewer limits must be 1..100 iterations and 0..100 tests")
	}
	if r.TimeoutSeconds < 1 || r.TimeoutSeconds > 1800 || r.MaxInputBytes < 4096 || r.MaxInputBytes > 2<<20 {
		return fmt.Errorf("reviewer time/input limits are out of bounds")
	}
	// An empty name disables the credential entirely, for a local provider
	// that takes none. Otherwise the name has to survive being pasted into a
	// compose file and appended to /run/secrets/.
	if strings.ContainsAny(r.APIKeyEnv, "=/\\ \t\x00\r\n") {
		return fmt.Errorf("reviewer.api_key_env must be an environment variable name")
	}
	for _, p := range c.SensitivePaths {
		if p == "" || strings.Contains(p, "\\") || strings.HasPrefix(p, "/") || strings.Contains(p, "..") {
			return fmt.Errorf("invalid sensitive path glob %q", p)
		}
		if _, err := path.Match(strings.ReplaceAll(p, "**", "*"), ""); err != nil {
			return fmt.Errorf("invalid sensitive path glob %q: %w", p, err)
		}
	}
	return nil
}

// Runtime is the reviewer configuration a run actually uses: the committed
// policy after the deployment environment and the Docker secret are applied.
// Sources records where each value that did not come from the policy was
// taken from — the variable or file name, never the value itself.
type Runtime struct {
	Endpoint string
	Model    string
	APIKey   string
	Sources  []string
}

// ResolveReviewer applies the deployment environment over the trusted policy.
// getenv and readFile are injected so resolution is testable without touching
// the process environment or the filesystem.
//
// The credential is looked up the way the cluster's own loader does it: a
// variable present in the environment wins, then <NAME>_FILE if the secret is
// mounted under another target, then /run/secrets/<NAME>, which is where the
// deployment mounts the secret it created from that variable. A file named
// explicitly must be readable; the conventional path simply being absent is
// not an error, but a mounted file that cannot be used is always reported
// instead of being silently skipped.
func (c Config) ResolveReviewer(getenv func(string) string, readFile func(string) ([]byte, error)) (Runtime, error) {
	if getenv == nil {
		getenv = func(string) string { return "" }
	}
	if readFile == nil {
		readFile = func(string) ([]byte, error) { return nil, fs.ErrNotExist }
	}
	r := Runtime{Endpoint: c.Reviewer.Endpoint, Model: c.Reviewer.Model}
	if v := strings.TrimSpace(getenv(EndpointEnv)); v != "" {
		r.Endpoint = v
		r.Sources = append(r.Sources, "endpoint from "+EndpointEnv)
	}
	// A blank variable means "unset", so an exported-but-empty value in a
	// compose file cannot silently disable the reviewer configured in policy.
	if v := strings.TrimSpace(getenv(ModelEnv)); v != "" {
		r.Model = v
		r.Sources = append(r.Sources, "model from "+ModelEnv)
	}
	name := strings.TrimSpace(c.Reviewer.APIKeyEnv)
	if name == "" {
		return r, nil
	}
	if key := getenv(name); key != "" {
		r.APIKey = key
		r.Sources = append(r.Sources, "API key from "+name)
		return r, nil
	}
	file, explicit := strings.TrimSpace(getenv(name+FileEnvSuffix)), true
	if file == "" {
		file, explicit = SecretsDir+"/"+name, false
	}
	key, err := readSecret(file, readFile)
	switch {
	case err == nil:
		r.APIKey = key
		r.Sources = append(r.Sources, "API key from "+file)
	case explicit || !errors.Is(err, fs.ErrNotExist):
		return Runtime{}, fmt.Errorf("reviewer API key secret %s: %w", file, err)
	}
	return r, nil
}

// A Docker secret is a file whose whole content is the credential, and both
// the deployment and editors routinely leave a trailing newline, so
// surrounding whitespace is not part of the key. Anything else that would make
// the key unusable as an Authorization header is rejected here, where the file
// can be named, rather than inside the request.
func readSecret(file string, readFile func(string) ([]byte, error)) (string, error) {
	data, err := readFile(file)
	if err != nil {
		return "", err
	}
	if len(data) > 8192 {
		return "", fmt.Errorf("secret exceeds 8 KiB")
	}
	key := strings.TrimSpace(string(data))
	if key == "" {
		return "", fmt.Errorf("secret is empty")
	}
	if strings.ContainsAny(key, "\r\n\x00") {
		return "", fmt.Errorf("secret must be a single line")
	}
	return key, nil
}
