package config

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

// preparePolicy returns the members of a policy whose prepare object is the
// documented Go recipe with extra fields merged in.
func preparePolicy(t *testing.T, extra map[string]any) string {
	t.Helper()
	p := map[string]any{"command": []string{"go", "mod", "download"}, "inputs": []string{"go.mod", "go.sum"}}
	for k, v := range extra {
		p[k] = v
	}
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	return `,"prepare":` + string(b)
}

func TestPrepareAcceptsTheDocumentedRecipes(t *testing.T) {
	for _, extra := range []map[string]any{
		nil,
		{"network": true, "user": "sandbox", "timeout_seconds": 900},
		{"inputs": []string{"go.work", "go.work.sum", "app/go.mod", "app/go.sum"}},
		{"user": "root", "inputs": []string{"package.json", "package-lock.json"}, "command": []string{"sh", "-c", "cp package.json package-lock.json / && cd / && npm ci --ignore-scripts"}},
		{"inputs": []string{"requirements*.txt", "src/*/pyproject.toml", "a?.lock", "[ab].json"}},
		{"env": map[string]string{"GOMODCACHE": "/opt/gomod", "NODE_PATH": "/opt/node_modules", "_X9": ""}},
		{"max_added_mb": 1}, {"max_added_mb": 65536}, {"timeout_seconds": 1}, {"timeout_seconds": 3600},
	} {
		c, err := policy(preparePolicy(t, extra))
		if err != nil {
			t.Errorf("%v rejected: %v", extra, err)
			continue
		}
		if c.Prepare == nil {
			t.Errorf("%v decoded without a prepare object", extra)
		}
	}
}

func TestPrepareRejects(t *testing.T) {
	many := func(n int, f func(int) string) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = f(i)
		}
		return out
	}
	env := func(n int) map[string]string {
		out := map[string]string{}
		for i := 0; i < n; i++ {
			out[fmt.Sprintf("V%d", i)] = "x"
		}
		return out
	}
	for name, extra := range map[string]map[string]any{
		"empty command":           {"command": []string{}},
		"blank argv0":             {"command": []string{" ", "x"}},
		"too many arguments":      {"command": many(129, func(int) string { return "x" })},
		"NUL in command":          {"command": []string{"go", "mod\x00"}},
		"oversized argument":      {"command": []string{"go", strings.Repeat("x", 16385)}},
		"file placeholder":        {"command": []string{"go", "{file}"}},
		"package placeholder":     {"command": []string{"go", "mod", "download", "{package}"}},
		"coverage placeholder":    {"command": []string{"go", "-o={coverage_out}"}},
		"results placeholder":     {"command": []string{"go", "{results_out}"}},
		"no inputs":               {"inputs": []string{}},
		"too many inputs":         {"inputs": many(65, func(i int) string { return fmt.Sprintf("f%d", i) })},
		"empty pattern":           {"inputs": []string{""}},
		"oversized pattern":       {"inputs": []string{strings.Repeat("a", 513)}},
		"NUL pattern":             {"inputs": []string{"go.mod\x00"}},
		"backslash":               {"inputs": []string{`app\go.mod`}},
		"absolute":                {"inputs": []string{"/etc/passwd"}},
		"dot slash":               {"inputs": []string{"./go.mod"}},
		"dot segment":             {"inputs": []string{"app/./go.mod"}},
		"dot-dot segment":         {"inputs": []string{"../go.mod"}},
		"empty segment":           {"inputs": []string{"app//go.mod"}},
		"trailing slash":          {"inputs": []string{"app/"}},
		"recursive glob":          {"inputs": []string{"**/go.mod"}},
		"git segment":             {"inputs": []string{".git/config"}},
		"git segment folded case": {"inputs": []string{"sub/.GIT/config"}},
		"bad pattern":             {"inputs": []string{"[go.mod"}},
		"unknown user":            {"user": "admin"},
		"negative timeout":        {"timeout_seconds": -1},
		"timeout too large":       {"timeout_seconds": 3601},
		"too many env":            {"env": env(33)},
		"lowercase env":           {"env": map[string]string{"gopath": "/x"}},
		"env starting with digit": {"env": map[string]string{"1X": "/x"}},
		"env name too long":       {"env": map[string]string{"A" + strings.Repeat("B", 64): "/x"}},
		"HOME":                    {"env": map[string]string{"HOME": "/x"}},
		"TMPDIR":                  {"env": map[string]string{"TMPDIR": "/x"}},
		"GOCACHE":                 {"env": map[string]string{"GOCACHE": "/x"}},
		"GOTOOLCHAIN":             {"env": map[string]string{"GOTOOLCHAIN": "auto"}},
		"GOPROXY":                 {"env": map[string]string{"GOPROXY": "https://x"}},
		"GOSUMDB":                 {"env": map[string]string{"GOSUMDB": "off"}},
		"SWIFTPROOF_ prefix":      {"env": map[string]string{"SWIFTPROOF_X": "1"}},
		"value too long":          {"env": map[string]string{"X": strings.Repeat("v", 4097)}},
		"value with newline":      {"env": map[string]string{"X": "a\nb"}},
		"value with CR":           {"env": map[string]string{"X": "a\rb"}},
		"value with NUL":          {"env": map[string]string{"X": "a\x00b"}},
		"negative max_added_mb":   {"max_added_mb": -1},
		"max_added_mb too large":  {"max_added_mb": 65537},
		"unknown field":           {"shell": true},
	} {
		if _, err := policy(preparePolicy(t, extra)); err == nil {
			t.Errorf("%s: accepted %v", name, extra)
		}
	}
}

func TestPrepareEdgeValues(t *testing.T) {
	for _, extra := range []map[string]any{
		{"inputs": many64()},
		{"env": map[string]string{"A" + strings.Repeat("B", 63): strings.Repeat("v", 4096)}},
		{"command": append([]string{"go"}, make([]string, 127)...)},
	} {
		if _, err := policy(preparePolicy(t, extra)); err != nil {
			t.Errorf("edge value rejected: %v", err)
		}
	}
	if _, err := policy(`,"prepare":{"command":["go"],"inputs":["go.mod"],"env":{"X":"1","x":"2"}}`); err == nil {
		t.Error("duplicate env names differing only in case accepted")
	}
	c, err := policy(`,"prepare":null`)
	if err != nil || c.Prepare != nil {
		t.Fatalf("null prepare: %+v, %v", c.Prepare, err)
	}
}

func many64() []string {
	out := make([]string, 64)
	for i := range out {
		out[i] = fmt.Sprintf("dir%d/go.mod", i)
	}
	return out
}

func TestPrepareEffectiveValues(t *testing.T) {
	var absent *Prepare
	if absent.EffectiveUser() != PrepareUserSandbox || absent.EffectiveTimeout() != 600*time.Second || absent.EffectiveMaxAddedMB() != 4096 {
		t.Fatal("nil prepare does not resolve to the defaults")
	}
	p := &Prepare{}
	if p.EffectiveUser() != "sandbox" || p.EffectiveTimeout() != 600*time.Second || p.EffectiveMaxAddedMB() != 4096 {
		t.Fatalf("zero values resolve to %q %v %d", p.EffectiveUser(), p.EffectiveTimeout(), p.EffectiveMaxAddedMB())
	}
	p = &Prepare{User: "root", TimeoutSeconds: 30, MaxAddedMB: 10}
	if p.EffectiveUser() != "root" || p.EffectiveTimeout() != 30*time.Second || p.EffectiveMaxAddedMB() != 10 {
		t.Fatalf("explicit values resolve to %q %v %d", p.EffectiveUser(), p.EffectiveTimeout(), p.EffectiveMaxAddedMB())
	}
}
