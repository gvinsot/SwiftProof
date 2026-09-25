package config

import (
	"encoding/json"
	"io/fs"
	"reflect"
	"strings"
	"testing"
)

func TestRoundTripDefaults(t *testing.T) {
	for _, lang := range []string{"go", "typescript", "python", "unknown"} {
		c := Default(lang)
		b, err := json.Marshal(c)
		if err != nil {
			t.Fatal(err)
		}
		got, err := Decode(b)
		if err != nil {
			t.Fatal(err)
		}
		if got.Sandbox.Network {
			t.Fatal("network enabled by default")
		}
	}
}
func TestRejectInvalidPolicy(t *testing.T) {
	for _, input := range []string{
		`{"version":2}`, `{"version":1,"secret":"oops"}`, `{"version":1} {}`,
		`{"commands":{"test":"go test ./..."}}`, `{"commands":{"shell":["sh"]}}`,
		`{"sandbox":{"timeout_seconds":0}}`, `{"sandbox":{"image":"--privileged"}}`,
		`{"reviewer":{"max_iterations":100000}}`, `{"sensitive_paths":["../outside"]}`,
		`null`, `{"version":1,"version":2}`, `{"version":1,"Version":1}`,
		`{"sandbox":{"network":false,"network":true}}`,
	} {
		if _, err := Decode([]byte(input)); err == nil {
			t.Errorf("accepted %s", input)
		}
	}
}

// The coverage command is the only command whose argv SwiftProof rewrites, so
// its profile destination must be unambiguous: the token the operator wrote is
// expanded in place, exactly once, and no flag is ever appended behind it.
func TestRejectInvalidCoverageCommand(t *testing.T) {
	const tokenReason = "command coverage must write its profile to {coverage_out}"
	for name, tc := range map[string]struct{ policy, want string }{
		"no token": {
			`{"version":1,"commands":{"coverage":["go","test","./..."]}}`, tokenReason},
		"token twice in one argument": {
			`{"version":1,"commands":{"coverage":["go","test","-coverprofile={coverage_out}{coverage_out}","./..."]}}`, tokenReason},
		"token in two arguments": {
			`{"version":1,"commands":{"coverage":["go","test","-coverprofile={coverage_out}","-o","{coverage_out}","./..."]}}`, tokenReason},
		"empty argv": {
			`{"version":1,"commands":{"coverage":[]}}`, "command coverage must be a nonempty argv array (at most 128 arguments)"},
	} {
		_, err := Decode([]byte(tc.policy))
		if err == nil {
			t.Errorf("%s: accepted coverage command %s", name, tc.policy)
			continue
		}
		if err.Error() != tc.want {
			t.Errorf("%s: rejection reason is %q, want %q", name, err.Error(), tc.want)
		}
	}
}

// A well-formed coverage command decodes byte for byte: the reviewed argv is
// the executed argv.
func TestAcceptCoverageCommand(t *testing.T) {
	const policy = `{"version":1,"language":"go","commands":{"test":["go","test","./..."],"coverage":["go","test","-covermode=count","-coverprofile={coverage_out}","./..."]}}`
	got, err := Decode([]byte(policy))
	if err != nil {
		t.Fatalf("well-formed coverage command rejected: %v", err)
	}
	want := []string{"go", "test", "-covermode=count", "-coverprofile={coverage_out}", "./..."}
	if !reflect.DeepEqual(got.Commands["coverage"], want) {
		t.Fatalf("coverage argv decoded as %q, want %q", got.Commands["coverage"], want)
	}
}

func TestDefaultGoSeedsCoverage(t *testing.T) {
	want := []string{"go", "test", "-covermode=count", "-coverprofile={coverage_out}", "./..."}
	if got := Default("go").Commands["coverage"]; !reflect.DeepEqual(got, want) {
		t.Fatalf("Default(\"go\") seeds coverage as %q, want %q", got, want)
	}
	if err := Default("go").Validate(); err != nil {
		t.Fatalf("seeded Go default does not validate: %v", err)
	}
	// The stock Node and Python images ship no coverage tool, so a seeded
	// default there would exit 127 and turn an optional measurement into a
	// failed run; those languages must stay unconfigured.
	for _, lang := range []string{"typescript", "javascript", "python", "unknown"} {
		if argv, ok := Default(lang).Commands["coverage"]; ok {
			t.Errorf("Default(%q) seeds a coverage command %q", lang, argv)
		}
	}
}

// The seeded policy has to survive the file it is written to: a default that
// decodes into something else would run an argv nobody reviewed.
func TestDefaultsRoundTripThroughDecode(t *testing.T) {
	c := Default("go")
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(b)
	if err != nil {
		t.Fatalf("marshalled Go default rejected: %v", err)
	}
	if !reflect.DeepEqual(got, c) {
		t.Fatalf("round trip changed the policy:\n got %+v\nwant %+v", got, c)
	}
	if err := got.Validate(); err != nil {
		t.Fatalf("round-tripped Go default does not validate: %v", err)
	}
}

// Coverage is opt-in: a policy written before the feature existed still decodes
// and validates, and decoding must not invent a coverage command for it.
func TestDecodeWithoutCoverageStaysValid(t *testing.T) {
	const policy = `{"version":1,"language":"go","commands":{"test":["go","test","./..."],"typecheck":["go","vet","./..."],"build":["go","build","./..."],"generated_test":["go","test","{package}"]}}`
	got, err := Decode([]byte(policy))
	if err != nil {
		t.Fatalf("legacy policy without a coverage command rejected: %v", err)
	}
	if argv, ok := got.Commands["coverage"]; ok {
		t.Fatalf("decode invented a coverage command %q", argv)
	}
	if len(got.Commands) != 4 {
		t.Fatalf("decoded %d commands, want only the 4 legacy commands", len(got.Commands))
	}
	if err := got.Validate(); err != nil {
		t.Fatalf("legacy policy without a coverage command does not validate: %v", err)
	}
}

// The deployment, not the reviewed repository, owns the provider: endpoint and
// model arrive as variables and the credential as a mounted Docker secret,
// while the trusted policy keeps deciding everything else.
func TestResolveReviewerFromDeployment(t *testing.T) {
	const secret = "/run/secrets/SWIFTPROOF_API_KEY"
	files := map[string]string{
		secret:             "secret-key\n",
		"/run/secrets/alt": "alt-key",
		"/run/secrets/bad": "line\nbreak",
		"/run/secrets/nil": "  \n",
	}
	read := func(name string) ([]byte, error) {
		content, ok := files[name]
		if !ok {
			return nil, fs.ErrNotExist
		}
		return []byte(content), nil
	}
	for name, tc := range map[string]struct {
		env                     map[string]string
		wantEndpoint, wantModel string
		wantKey, wantSource     string
		wantErr                 string
	}{
		"policy alone": {
			wantEndpoint: "https://api.openai.com/v1/chat/completions"},
		"environment overrides policy": {
			env:          map[string]string{EndpointEnv: "https://provider.internal/v1", ModelEnv: "deployed-model"},
			wantEndpoint: "https://provider.internal/v1", wantModel: "deployed-model",
			wantKey: "secret-key", wantSource: "endpoint from " + EndpointEnv},
		"blank variables leave policy in place": {
			env:          map[string]string{EndpointEnv: "  ", ModelEnv: ""},
			wantEndpoint: "https://api.openai.com/v1/chat/completions", wantKey: "secret-key"},
		"mounted secret supplies the credential": {
			env:          map[string]string{},
			wantEndpoint: "https://api.openai.com/v1/chat/completions",
			wantKey:      "secret-key", wantSource: "API key from " + secret},
		"variable wins over the mounted secret": {
			env:          map[string]string{"SWIFTPROOF_API_KEY": "environment-key"},
			wantEndpoint: "https://api.openai.com/v1/chat/completions",
			wantKey:      "environment-key", wantSource: "API key from SWIFTPROOF_API_KEY"},
		"secret mounted under another target": {
			env:          map[string]string{"SWIFTPROOF_API_KEY_FILE": "/run/secrets/alt"},
			wantEndpoint: "https://api.openai.com/v1/chat/completions",
			wantKey:      "alt-key", wantSource: "API key from /run/secrets/alt"},
		"explicitly named secret must exist": {
			env:     map[string]string{"SWIFTPROOF_API_KEY_FILE": "/run/secrets/absent"},
			wantErr: "reviewer API key secret /run/secrets/absent"},
		"unusable secret is reported": {
			env:     map[string]string{"SWIFTPROOF_API_KEY_FILE": "/run/secrets/bad"},
			wantErr: "secret must be a single line"},
		"empty secret is reported": {
			env:     map[string]string{"SWIFTPROOF_API_KEY_FILE": "/run/secrets/nil"},
			wantErr: "secret is empty"},
	} {
		t.Run(name, func(t *testing.T) {
			c := Default("go")
			get := func(variable string) string { return tc.env[variable] }
			// Without an environment there is no secrets directory either: a
			// developer running the binary locally keeps the policy values.
			source := read
			if tc.env == nil {
				source = func(string) ([]byte, error) { return nil, fs.ErrNotExist }
			}
			got, err := c.ResolveReviewer(get, source)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error is %v, want one containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolution failed: %v", err)
			}
			if got.Endpoint != tc.wantEndpoint || got.Model != tc.wantModel || got.APIKey != tc.wantKey {
				t.Fatalf("resolved %q/%q/%q, want %q/%q/%q", got.Endpoint, got.Model, got.APIKey, tc.wantEndpoint, tc.wantModel, tc.wantKey)
			}
			joined := strings.Join(got.Sources, "; ")
			if tc.wantSource != "" && !strings.Contains(joined, tc.wantSource) {
				t.Fatalf("sources are %q, want one containing %q", joined, tc.wantSource)
			}
			// Sources are printed and may be logged: they name where a value
			// came from, never the credential itself.
			if got.APIKey != "" && strings.Contains(joined, got.APIKey) {
				t.Fatalf("sources disclose the credential: %q", joined)
			}
		})
	}
}

// An absent secret leaves the environment variable in charge, so a shell or CI
// setup that never mounts one keeps working unchanged.
func TestResolveReviewerWithoutSecretsDirectory(t *testing.T) {
	c := Default("go")
	c.Reviewer.Model = "policy-model"
	got, err := c.ResolveReviewer(func(string) string { return "" }, nil)
	if err != nil {
		t.Fatalf("absent secret must not fail the run: %v", err)
	}
	if got.Model != "policy-model" || got.APIKey != "" || len(got.Sources) != 0 {
		t.Fatalf("resolved %+v, want the policy model and no credential", got)
	}
}

func TestResultsPlaceholderOnlyOnceInGeneratedTest(t *testing.T) {
	if argv := Default("typescript").Commands["generated_test"]; strings.Count(strings.Join(argv, " "), ResultsPlaceholder) != 1 {
		t.Fatalf("TypeScript default %q does not write a verifiable report", argv)
	}
	for _, commands := range []map[string][]string{
		{"test": {"npx", "vitest", "--outputFile=" + ResultsPlaceholder}},
		{"generated_test": {"npx", "vitest", "{file}", "--outputFile=" + ResultsPlaceholder, ResultsPlaceholder}},
	} {
		c := Default("typescript")
		c.Commands = commands
		if err := c.Validate(); err == nil {
			t.Errorf("accepted %q", commands)
		}
	}
}
