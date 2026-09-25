package config

import (
	"encoding/json"
	"strings"
	"testing"
)

// mutationPolicy returns the members of a policy whose mutation object uses
// argv and the given budget.
func mutationPolicy(t *testing.T, argv []string, maxMutants, timeout, runtime int) string {
	t.Helper()
	command, err := json.Marshal(argv)
	if err != nil {
		t.Fatal(err)
	}
	return `,"mutation":{"command":` + string(command) + `,"max_mutants":` + itoa(maxMutants) + `,"timeout_seconds":` + itoa(timeout) + `,"max_runtime_seconds":` + itoa(runtime) + `}`
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}

var goodMutationCommand = []string{"go", "test", "-json", "-count=1", "-failfast", "{package}"}

func TestMutationAcceptsTheDocumentedPolicy(t *testing.T) {
	c, err := policy(mutationPolicy(t, goodMutationCommand, 20, 60, 300))
	if err != nil {
		t.Fatalf("documented mutation policy rejected: %v", err)
	}
	if c.Mutation == nil || c.Mutation.MaxMutants != 20 || strings.Join(c.Mutation.Command, " ") != strings.Join(goodMutationCommand, " ") {
		t.Fatalf("decoded %+v", c.Mutation)
	}
	for _, argv := range [][]string{
		{"go", "test", "-json", "{package}"},
		{"/usr/local/go/bin/go", "test", "{package}", "-json", "--count=1", "-timeout=30s", "-v"},
	} {
		if _, err := policy(mutationPolicy(t, argv, 1, 1, 1)); err != nil {
			t.Errorf("%q rejected: %v", argv, err)
		}
	}
}

func TestMutationRejectsCommands(t *testing.T) {
	long := strings.Repeat("x", 16385)
	many := []string{"go", "test", "-json", "{package}"}
	for len(many) < 129 {
		many = append(many, "-v")
	}
	for name, argv := range map[string][]string{
		"too short":            {"go", "test"},
		"too many arguments":   many,
		"oversized argument":   {"go", "test", "-json", "{package}", "-tags=" + long},
		"NUL":                  {"go", "test", "-json", "{package}", "-v\x00"},
		"not go":               {"gotest", "test", "-json", "{package}"},
		"not test":             {"go", "vet", "-json", "{package}"},
		"no package":           {"go", "test", "-json", "./..."},
		"two packages":         {"go", "test", "-json", "{package}", "{package}"},
		"embedded package":     {"go", "test", "-json", "./{package}"},
		"file placeholder":     {"go", "test", "-json", "{package}", "-coverprofile={file}"},
		"coverage placeholder": {"go", "test", "-json", "{package}", "-coverprofile={coverage_out}"},
		"results placeholder":  {"go", "test", "-json", "{package}", "-o={results_out}"},
		"no json":              {"go", "test", "{package}"},
		"double-dash json":     {"go", "test", "--json", "{package}"},
		"duplicate json":       {"go", "test", "-json", "-json", "{package}"},
		"json with value":      {"go", "test", "-json", "-json=true", "{package}"},
		"positional":           {"go", "test", "-json", "{package}", "./other"},
		"separated flag value": {"go", "test", "-json", "{package}", "-timeout", "30s"},
		"double dash":          {"go", "test", "-json", "{package}", "--"},
		"args":                 {"go", "test", "-json", "{package}", "-args"},
		"C":                    {"go", "test", "-json", "{package}", "-C=/tmp"},
		"exec":                 {"go", "test", "-json", "{package}", "-exec=true"},
		"overlay":              {"go", "test", "-json", "{package}", "--overlay=o.json"},
		"run":                  {"go", "test", "-json", "{package}", "-run=TestX"},
		"double-dash run":      {"go", "test", "-json", "{package}", "--run=TestX"},
		"skip":                 {"go", "test", "-json", "{package}", "-skip=TestX"},
		"list":                 {"go", "test", "-json", "{package}", "-list=."},
		"c":                    {"go", "test", "-json", "{package}", "-c"},
		"o":                    {"go", "test", "-json", "{package}", "-o=bin"},
		"fuzz":                 {"go", "test", "-json", "{package}", "-fuzz=FuzzX"},
		"test.run":             {"go", "test", "-json", "{package}", "-test.run=TestX"},
		"test.v":               {"go", "test", "-json", "{package}", "-test.v"},
		"lone dash":            {"go", "test", "-json", "{package}", "-"},
		"bare equals":          {"go", "test", "-json", "{package}", "-=x"},
	} {
		if _, err := policy(mutationPolicy(t, argv, 10, 60, 300)); err == nil {
			t.Errorf("%s: accepted %q", name, argv)
		}
	}
}

func TestMutationBudgetsAtEdges(t *testing.T) {
	// The default sandbox allows 120 s per run and 600 s in total.
	for _, tc := range []struct {
		maxMutants, timeout, runtime int
		ok                           bool
	}{
		{1, 1, 1, true},
		{200, 120, 600, true},
		{0, 60, 300, false},
		{-1, 60, 300, false},
		{201, 60, 300, false},
		{10, 0, 300, false},
		{10, -1, 300, false},
		{10, 121, 600, false},
		{10, 60, 0, false},
		{10, 60, 59, false},
		{10, 60, 60, true},
		{10, 60, 601, false},
	} {
		_, err := policy(mutationPolicy(t, goodMutationCommand, tc.maxMutants, tc.timeout, tc.runtime))
		if tc.ok && err != nil {
			t.Errorf("%+v rejected: %v", tc, err)
		}
		if !tc.ok && err == nil {
			t.Errorf("%+v accepted", tc)
		}
	}
}

func TestMutationRequiresEveryField(t *testing.T) {
	for _, members := range []string{
		`,"mutation":{}`,
		`,"mutation":{"command":["go","test","-json","{package}"]}`,
		`,"mutation":{"max_mutants":1,"timeout_seconds":1,"max_runtime_seconds":1}`,
		`,"mutation":{"command":["go","test","-json","{package}"],"max_mutants":1,"timeout_seconds":1}`,
		`,"mutation":{"command":["go","test","-json","{package}"],"max_mutants":1,"timeout_seconds":1,"max_runtime_seconds":1,"extra":true}`,
	} {
		if _, err := policy(members); err == nil {
			t.Errorf("accepted %s", members)
		}
	}
	c, err := policy(`,"mutation":null`)
	if err != nil || c.Mutation != nil {
		t.Fatalf("null mutation: %+v, %v", c.Mutation, err)
	}
}

func TestFlagName(t *testing.T) {
	for in, want := range map[string]string{"-run": "run", "--run=x": "run", "-count=1": "count", "---x": "-x", "-": "", "-=v": ""} {
		if got := flagName(in); got != want {
			t.Errorf("flagName(%q) = %q, want %q", in, got, want)
		}
	}
}
