package linter

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gvinsot/SwiftProof/internal/gitrepo"
	"github.com/gvinsot/SwiftProof/internal/model"
)

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	c := exec.Command("git", append([]string{"-C", dir}, args...)...)
	c.Env = append(os.Environ(), "GIT_AUTHOR_NAME=Test", "GIT_AUTHOR_EMAIL=test@example.invalid", "GIT_COMMITTER_NAME=Test", "GIT_COMMITTER_EMAIL=test@example.invalid")
	b, err := c.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v %s", args, err, b)
	}
	return strings.TrimSpace(string(b))
}
func put(t *testing.T, dir, p, s string) {
	t.Helper()
	target := filepath.Join(dir, p)
	if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte(s), 0600); err != nil {
		t.Fatal(err)
	}
}
func commit(t *testing.T, dir string) string {
	t.Helper()
	git(t, dir, "add", "-A")
	git(t, dir, "commit", "--no-gpg-sign", "-m", "test")
	return git(t, dir, "rev-parse", "HEAD")
}

func TestAnalyzeRealChangesAndDeterminism(t *testing.T) {
	dir := t.TempDir()
	git(t, dir, "init", "-b", "main")
	git(t, dir, "config", "core.autocrlf", "false")
	put(t, dir, "auth/service.go", "package auth\ntype User struct { Name string }\nfunc Login(name string) bool { return true }\nfunc Stable() int { return 1 }\n")
	put(t, dir, "src/api.ts", "export function pay(input: string) {\n validateInput(input);\n return input;\n}\n")
	base := commit(t, dir)
	put(t, dir, "auth/service.go", "package auth\ntype User struct { Name string; Roles []string }\nfunc Login(name string, jwt string) bool { return true }\nfunc Stable() int { return 2 }\n")
	put(t, dir, "src/api.ts", "export function pay(input: string) {\n // TODO: validate\n return fetch(\"https://service.invalid\") as any;\n}\n")
	put(t, dir, "go.mod", "module example.invalid/app\ngo 1.23\n")
	head := commit(t, dir)
	r, err := gitrepo.Open(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	change, err := r.Analyze(context.Background(), base, head, false)
	if err != nil {
		t.Fatal(err)
	}
	signals, err := Analyze(context.Background(), r, change, []string{"**/auth/**"})
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]bool{}
	symbols := map[string]bool{}
	for _, s := range signals {
		kinds[s.Kind] = true
		if s.Kind == "public_api_change" {
			symbols[s.Symbol] = true
		}
		if s.Line < 1 || s.ID == "" || (s.Side != "old" && s.Side != "new") {
			t.Errorf("incomplete signal %+v", s)
		}
		if s.Kind == "validation_removed" && (s.Side != "old" || s.Line != 2) {
			t.Errorf("wrong deleted validation location: %+v", s)
		}
	}
	for _, kind := range []string{"sensitive_path", "public_api_change", "auth_change", "validation_removed", "network_change", "type_suppression", "todo_added", "dependency_change", "no_test_change"} {
		if !kinds[kind] {
			t.Errorf("missing %s: %+v", kind, signals)
		}
	}
	if !symbols["Login"] || !symbols["User"] || symbols["Stable"] {
		t.Errorf("wrong AST declaration detection: %+v", symbols)
	}
	first, _ := json.Marshal(signals)
	for n := 0; n < 4; n++ {
		again, err := Analyze(context.Background(), r, change, []string{"**/auth/**"})
		if err != nil {
			t.Fatal(err)
		}
		serialized, _ := json.Marshal(again)
		if string(serialized) != string(first) {
			t.Fatal("nondeterministic signal ordering or IDs")
		}
	}
}

func TestGoDeclarationsSignatures(t *testing.T) {
	before := []byte("package api\n// Comment\ntype Store interface { Read(string) ([]byte, error) }\ntype Item[T any] struct { Value T }\nfunc (i *Item[T]) Get() T { return i.Value }\nconst ( hidden = iota; Answer )\nvar Name string = \"before\"\n")
	a, err := goDeclarations("a.go", before)
	if err != nil {
		t.Fatal(err)
	}
	after := []byte("package api\n// New documentation\ntype Store interface { Read(string) ([]byte, error) }\ntype Item[T any] struct { Value T }\nfunc (i *Item[T]) Get() T { panic(\"changed body\") }\nconst ( hidden = iota; Answer )\nvar Name string = \"after\"\n")
	b, err := goDeclarations("a.go", after)
	if err != nil {
		t.Fatal(err)
	}
	for name, d := range a {
		if b[name].signature != d.signature {
			t.Errorf("body or comment altered %s: %q != %q", name, d.signature, b[name].signature)
		}
	}
	if !strings.Contains(a["Answer"].signature, "iota=1") {
		t.Errorf("implicit const lost: %+v", a["Answer"])
	}
	if _, ok := a["Item.Get"]; !ok {
		t.Fatalf("generic receiver key: %+v", a)
	}
	if _, err := goDeclarations("bad.go", []byte("package broken\nfunc")); err == nil {
		t.Fatal("invalid AST accepted")
	}
}

func TestSensitiveGoFunctionBodyChanges(t *testing.T) {
	base := "package policy\n\nfunc Authorize(role string) bool {\n\treturn role == \"admin\"\n}\n\nfunc Nearby() int { return 1 }\n"
	cases := []struct {
		name, before, after, symbol, kind, side string
		line, end                               int
	}{
		{"unchanged_signature", base, strings.Replace(base, `role == "admin"`, `role != ""`, 1), "Authorize", "auth_change", "new", 4, 4},
		{"private_function", strings.Replace(base, "Authorize", "authorize", 1), strings.Replace(strings.Replace(base, "Authorize", "authorize", 1), `role == "admin"`, `role != ""`, 1), "authorize", "auth_change", "new", 4, 4},
		{"receiver_context", "package policy\ntype PaymentService struct{}\nfunc (s PaymentService) process(amount int) int {\n return amount\n}\n", "package policy\ntype PaymentService struct{}\nfunc (s PaymentService) process(amount int) int {\n return amount * 2\n}\n", "PaymentService.process", "sensitive_function_change", "new", 4, 4},
		{"nearby_context_only", base, strings.Replace(base, "return 1", "return 2", 1), "", "", "", 0, 0},
		{"whitespace_only", base, strings.Replace(base, "\treturn role == \"admin\"", "\n    return role==\"admin\"\n", 1), "", "", "", 0, 0},
		{"comment_only", base, strings.Replace(base, "\treturn role", "\t// Different documentation.\n\treturn role", 1), "", "", "", 0, 0},
		{"removed_guard", "package policy\n\nfunc Authorize(role string) bool {\n if role == \"\" {\n  return false\n }\n return role == \"admin\"\n}\n", "package policy\n\nfunc Authorize(role string) bool {\n return role == \"admin\"\n}\n", "Authorize", "auth_change", "old", 4, 6},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			git(t, dir, "init", "-b", "main")
			git(t, dir, "config", "core.autocrlf", "false")
			put(t, dir, "policy.go", tc.before)
			before := commit(t, dir)
			put(t, dir, "policy.go", tc.after)
			after := commit(t, dir)
			repo, err := gitrepo.Open(context.Background(), dir)
			if err != nil {
				t.Fatal(err)
			}
			change, err := repo.Analyze(context.Background(), before, after, false)
			if err != nil {
				t.Fatal(err)
			}
			signals, err := Analyze(context.Background(), repo, change, nil)
			if err != nil {
				t.Fatal(err)
			}
			var contextual []model.Signal
			for _, signal := range signals {
				if signal.Symbol != "" && (signal.Kind == "auth_change" || signal.Kind == "sensitive_function_change") {
					contextual = append(contextual, signal)
				}
				if tc.name == "unchanged_signature" && signal.Kind == "public_api_change" {
					t.Fatalf("body-only change classified as API change: %+v", signal)
				}
			}
			if tc.symbol == "" {
				if len(contextual) != 0 {
					t.Fatalf("unchanged function body flagged: %+v", contextual)
				}
				return
			}
			if len(contextual) != 1 {
				t.Fatalf("expected one contextual signal, got %+v (all: %+v)", contextual, signals)
			}
			s := contextual[0]
			if s.Symbol != tc.symbol || s.Kind != tc.kind || s.Side != tc.side || s.Line != tc.line || s.EndLine != tc.end || s.Severity != "high" {
				t.Errorf("incorrect body signal %+v", s)
			}
			if !strings.Contains(s.Evidence, "heuristic") || !strings.Contains(s.Evidence, "not a verified vulnerability") {
				t.Errorf("overstated evidence: %s", s.Evidence)
			}
		})
	}
}

func TestBodyTokensPreserveStringLiterals(t *testing.T) {
	if bodyTokens(`{ return "admin user" }`) == bodyTokens(`{ return "adminuser" }`) {
		t.Fatal("literal whitespace was erased")
	}
	if bodyTokens("{\n return true // comment\n}") != bodyTokens("{ return true; }") {
		t.Fatal("comments or formatting changed body fingerprint")
	}
}

func TestGlobZeroOrMoreDirectories(t *testing.T) {
	for _, test := range []struct {
		pattern, path string
		match         bool
	}{
		{"**/auth/**", "auth/login.go", true}, {"**/auth/**", "src/auth/login.go", true}, {"**/auth/**", "authentication.go", false},
		{"**/payment*/**", "payments/pay.go", true}, {"**/payment*/**", "src/payment/pay.go", true}, {"src/*/a?.go", "src/x/ab.go", true}, {"src/*/a?.go", "src/x/y/ab.go", false},
	} {
		re, err := compileGlob(test.pattern)
		if err != nil {
			t.Fatal(err)
		}
		if re.MatchString(test.path) != test.match {
			t.Errorf("%s on %s", test.pattern, test.path)
		}
	}
	if _, err := compileGlob("/absolute/**"); err == nil {
		t.Fatal("absolute glob accepted")
	}
}

func TestNoTestChangeIsOnlyHeuristicAndTestDeletionDoesNotCount(t *testing.T) {
	change := model.Change{Files: []model.ChangedFile{{Path: "src/pay.ts", Status: "M", Additions: 1, Hunks: []model.Hunk{{Lines: []model.DiffLine{{Kind: "add", NewLine: 3, Content: "return amount;"}}}}}, {Path: "src/pay.test.ts", Status: "D"}}}
	signals, err := Analyze(context.Background(), nil, change, nil)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, s := range signals {
		if s.Kind == "no_test_change" {
			found = true
			if !strings.Contains(s.Evidence, "not been measured") {
				t.Fatal("coverage disclaimer absent")
			}
		}
	}
	if !found {
		t.Fatal("deleted test incorrectly considered new coverage")
	}
	change.Files[1].Status = "M"
	signals, err = Analyze(context.Background(), nil, change, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range signals {
		if s.Kind == "no_test_change" {
			t.Fatal("nearby changed test missed")
		}
	}
}

func TestEmptyAndCanceled(t *testing.T) {
	signals, err := Analyze(context.Background(), nil, model.Change{}, nil)
	if err != nil || signals == nil || len(signals) != 0 {
		t.Fatalf("empty=%+v %v", signals, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Analyze(ctx, nil, model.Change{}, nil); err != context.Canceled {
		t.Fatalf("cancel=%v", err)
	}
}

func BenchmarkGoDeclarations(b *testing.B) {
	source := []byte("package example\ntype Store interface { Read(string) ([]byte,error); Write(string,[]byte) error }\ntype Record struct { ID string; Data []byte }\nfunc Load(id string) (*Record,error) { return nil,nil }\n")
	b.SetBytes(int64(len(source)))
	b.ReportAllocs()
	for n := 0; n < b.N; n++ {
		if _, err := goDeclarations("api.go", source); err != nil {
			b.Fatal(err)
		}
	}
}
func BenchmarkAnalyzePolyglot(b *testing.B) {
	change := model.Change{}
	for n := 0; n < 1000; n++ {
		change.Files = append(change.Files, model.ChangedFile{Path: fmt.Sprintf("src/module%d/service.ts", n), Status: "M", Additions: 1, Hunks: []model.Hunk{{Lines: []model.DiffLine{{Kind: "add", NewLine: 20, Content: `return fetch("https://example.invalid");`}}}}})
	}
	b.ReportAllocs()
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		if _, err := Analyze(context.Background(), nil, change, nil); err != nil {
			b.Fatal(err)
		}
	}
}
