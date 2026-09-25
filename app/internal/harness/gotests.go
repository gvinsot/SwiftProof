package harness

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/gvinsot/SwiftProof/app/internal/model"
)

// generatedGoTests validates runnable Go test declarations. Identifying test
// functions before execution lets us prove the generated test itself ran.
func generatedGoTests(path, source string) ([]string, error) {
	base := filepath.Base(path)
	if strings.HasPrefix(base, "_") || strings.HasPrefix(base, ".") {
		return nil, errors.New("Go ignores test filenames starting with _ or .")
	}
	file, err := parser.ParseFile(token.NewFileSet(), path, source, 0)
	if err != nil {
		return nil, fmt.Errorf("generated Go test has invalid syntax: %w", err)
	}
	testingName := ""
	for _, imp := range file.Imports {
		value, _ := strconv.Unquote(imp.Path.Value)
		if value == "testing" {
			testingName = "testing"
			if imp.Name != nil {
				testingName = imp.Name.Name
			}
		}
	}
	names := []string{}
	seen := map[string]bool{}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv != nil || !isGoTestName(fn.Name.Name) {
			continue
		}
		if fn.Type.TypeParams != nil || fn.Type.Results != nil && len(fn.Type.Results.List) > 0 || fn.Type.Params == nil || len(fn.Type.Params.List) != 1 || len(fn.Type.Params.List[0].Names) > 1 {
			return nil, fmt.Errorf("%s must have signature func %s(t *testing.T)", fn.Name.Name, fn.Name.Name)
		}
		star, ok := fn.Type.Params.List[0].Type.(*ast.StarExpr)
		if !ok {
			return nil, fmt.Errorf("%s requires a *testing.T parameter", fn.Name.Name)
		}
		selector, ok := star.X.(*ast.SelectorExpr)
		if !ok {
			return nil, fmt.Errorf("%s requires a named testing import and *testing.T parameter", fn.Name.Name)
		}
		pkg, ok := selector.X.(*ast.Ident)
		if !ok || pkg.Name != testingName || selector.Sel.Name != "T" || testingName == "" || testingName == "_" || testingName == "." {
			return nil, fmt.Errorf("%s requires a *testing.T parameter", fn.Name.Name)
		}
		if seen[fn.Name.Name] {
			return nil, fmt.Errorf("duplicate generated Go test %s", fn.Name.Name)
		}
		seen[fn.Name.Name] = true
		names = append(names, fn.Name.Name)
	}
	if len(names) == 0 {
		return nil, errors.New("generated Go file must declare at least one runnable TestX(t *testing.T) function")
	}
	return names, nil
}

func isGoTestName(name string) bool {
	if !strings.HasPrefix(name, "Test") {
		return false
	}
	tail := strings.TrimPrefix(name, "Test")
	if tail == "" {
		return true
	}
	r, _ := utf8.DecodeRuneInString(tail)
	return !unicode.IsLower(r)
}

func rejectGoTestCollisions(root, path string, names []string) error {
	if root == "" {
		return nil
	}
	dir := filepath.Join(root, filepath.Dir(filepath.FromSlash(path)))
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") {
			continue
		}
		b, err := readBounded(filepath.Join(dir, entry.Name()))
		if err != nil {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), entry.Name(), b, 0)
		if err != nil {
			continue
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil {
				continue
			}
			for _, name := range names {
				if fn.Name.Name == name {
					return fmt.Errorf("generated test name %s already exists in %s", name, entry.Name())
				}
			}
		}
	}
	return nil
}

func selectGoTests(command, names []string) []string {
	quoted := make([]string, len(names))
	for i, name := range names {
		quoted[i] = regexp.QuoteMeta(name)
	}
	return append(command, "-json", "-count=1", "-run", "^("+strings.Join(quoted, "|")+")$")
}

// Restrict verified Go execution to the injected file's one package. Multi-package
// commands, working-directory changes, overlays and external exec wrappers do not
// establish that the observed named test came from the generated source.
func verifiableGoTemplate(command []string) bool {
	if len(command) < 3 || filepath.Base(command[0]) != "go" || command[1] != "test" {
		return false
	}
	targets := 0
	for _, arg := range command[2:] {
		if arg == "{package}" || arg == "{file}" {
			targets++
			continue
		}
		if !strings.HasPrefix(arg, "-") || arg == "--" || arg == "-args" || arg == "-C" || strings.HasPrefix(arg, "-C=") || arg == "-exec" || strings.HasPrefix(arg, "-exec=") || arg == "-overlay" || strings.HasPrefix(arg, "-overlay=") {
			return false
		}
	}
	return targets == 1
}

// ValidateGoExecution rejects skipped, filtered, malformed, truncated, and package-
// only failures. It requires terminal events for the exact generated test names.
func ValidateGoExecution(check model.Check, names []string) model.Check {
	if check.Status != "PASS" && check.Status != "FAIL" {
		return check
	}
	if check.Truncated {
		check.Status = "ERROR"
		return check
	}
	wanted := map[string]bool{}
	for _, name := range names {
		wanted[name] = true
	}
	started := map[string]bool{}
	terminal := map[string]string{}
	packages := map[string]bool{}
	scanner := bufio.NewScanner(strings.NewReader(check.Output))
	scanner.Buffer(make([]byte, 4096), maxFileBytes)
	for scanner.Scan() {
		var event struct{ Action, Test, Package string }
		if json.Unmarshal(scanner.Bytes(), &event) != nil {
			continue
		}
		if !wanted[event.Test] {
			continue
		}
		packages[event.Package] = true
		switch event.Action {
		case "run":
			started[event.Test] = true
		case "pass", "fail", "skip":
			terminal[event.Test] = event.Action
		}
	}
	allPass := len(names) > 0
	failed := false
	for _, name := range names {
		allPass = allPass && started[name] && terminal[name] == "pass"
		failed = failed || started[name] && terminal[name] == "fail"
	}
	if check.Status == "PASS" && !allPass || check.Status == "FAIL" && !failed || scanner.Err() != nil || len(packages) != 1 {
		check.Status = "ERROR"
	}
	return check
}
