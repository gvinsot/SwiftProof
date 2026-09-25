package redact

import (
	"encoding/json"
	"math/rand"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestRedactMasksKnownCredentialShapes(t *testing.T) {
	cases := map[string]string{
		"private key":      "-----BEGIN RSA PRIVATE KEY-----\nMIIEabc\nxyz\n-----END RSA PRIVATE KEY-----",
		"unterminated key": "-----BEGIN PRIVATE KEY-----\nMIIEabc",
		"assignment":       "api_key=abc123",
		"json field":       `{"password":"hunter2"}`,
		"yaml field":       "client-secret: s3cr3t",
		"header":           "Authorization: tok3n-value",
		"bearer":           "curl -H 'x: Bearer abc.def-ghi'",
		"openai":           "key sk-abcdefghijklmnop",
		"github":           "ghp_abcdefghijklmnop and github_pat_abcdefghij",
		"aws":              "AKIAABCDEFGHIJKLMNOP",
		"jwt":              "eyJhbGciOiJI.eyJzdWIiOiIx.SflKxwRJSMeK",
		"url credentials":  "https://user:pa55@example.com/x",
	}
	secrets := []string{"MIIEabc", "abc123", "hunter2", "s3cr3t", "tok3n-value", "abc.def-ghi", "sk-abcdefghijklmnop", "ghp_abcdefghijklmnop", "github_pat_abcdefghij", "AKIAABCDEFGHIJKLMNOP", "SflKxwRJSMeK", "pa55"}
	for name, in := range cases {
		out := Redact(in)
		if !strings.Contains(out, Marker) {
			t.Errorf("%s: nothing redacted in %q", name, out)
		}
		for _, secret := range secrets {
			if strings.Contains(in, secret) && strings.Contains(out, secret) {
				t.Errorf("%s: %q leaked in %q", name, secret, out)
			}
		}
		if strings.Count(in, "\n") != strings.Count(out, "\n") {
			t.Errorf("%s: line count changed: %q -> %q", name, in, out)
		}
	}
}

func TestRedactLeavesOrdinaryTextAlone(t *testing.T) {
	for _, in := range []string{
		"",
		"ok  \texample.com/m\t0.01s",
		`{"numTotalTests":1,"testResults":[{"name":"a.test.ts","status":"passed"}]}`,
		"mode: set\nexample.com/m/store.go:5.2,6.9 1 0\n",
		"Discount(5,33) = 4",
		"see https://example.com/docs and user@example.com",
		Marker,
	} {
		if got := Redact(in); got != in {
			t.Errorf("Redact(%q) = %q, want unchanged", in, got)
		}
		if !IsFixedPoint(in) {
			t.Errorf("IsFixedPoint(%q) = false", in)
		}
	}
}

// redactionCorpus returns hand-written inputs, including JSON documents with
// secret-shaped values, plus deterministic random combinations of the
// fragments the rules react to.
func redactionCorpus() []string {
	corpus := []string{
		`{"password":"hunter2","token":"ghp_abcdefghijk12345","nested":{"api_key":"sk-aaaaaaaaaaaa"}}`,
		`{"results":[{"title":"password=abc","failureMessages":["Bearer abc.def","secret: x"]}]}`,
		`{"k":"password=[REDACTED]","v":"://u:[REDACTED]@h"}`,
		`[{"key":"Discount(5,33)","value":"authorization: Bearer eyJaaaaaaaaaa.bbbbbbbbbb.cccccccccc"}]`,
		"password=[REDACTED]",
		"password: ://user:pass@host",
		"password=,sk-abcdefghij",
		"password=\nBearer abc",
		"Bearer ://u:p@host",
		"sk-abc://u:p@host",
		"://sk-abcdefghijk:pw@host",
		"-----BEGIN EC PRIVATE KEY-----\npassword=x\n-----END EC PRIVATE KEY-----\nsecret=y",
		"-----BEGIN PRIVATE KEY-----\nno end password=1\n\n",
		"secret'password=abc",
		"password=a,secret=b}api-key:'c'",
		"AKIAABCDEFGHIJKLMNOPQRST",
		strings.Repeat("secret=", 50),
		"\"password\" : \"a b\"",
		"://0:://0:0@@", // found by FuzzRedactIdempotent: one pass leaves "://0:[REDACTED]@"
		"x://u:://v:w@@y",
		"password=://0:://0:0@@",
		strings.Repeat("://0:", 5) + "0@" + strings.Repeat("@", 5),
		strings.Repeat("://0:", 12) + "0@" + strings.Repeat("@", 12),
	}
	fragments := []string{
		"password", "passwd", "secret", "api_key", "API-KEY", "access_token", "auth-token", "client_secret", "Authorization",
		"=", ":", " ", "\t", "\n", "\"", "'", ",", "}", "{", "[", "]", "@", "/", "//", "://", ".",
		"Bearer ", "bearer\t", "sk-", "abcdefgh", "12345678", "ghp_", "gho_", "github_pat_", "AKIA", "ABCDEFGHIJKLMNOP",
		"eyJ", "eyJabcdefgh.", "ijklmnop.", "qrstuvwx", "user", "pass", "host",
		"-----BEGIN RSA PRIVATE KEY-----", "-----END RSA PRIVATE KEY-----", "-----BEGIN PRIVATE KEY-----",
		Marker, "é", "\u00ff", "x",
	}
	rng := rand.New(rand.NewSource(20260925))
	for i := 0; i < 20000; i++ {
		var b strings.Builder
		for n := 1 + rng.Intn(12); n > 0; n-- {
			b.WriteString(fragments[rng.Intn(len(fragments))])
		}
		corpus = append(corpus, b.String())
	}
	return corpus
}

func TestRedactIsIdempotent(t *testing.T) {
	for _, in := range redactionCorpus() {
		once := Redact(in)
		if twice := Redact(once); twice != once {
			t.Fatalf("Redact is not idempotent for %q:\nonce:  %q\ntwice: %q", in, once, twice)
		}
		if !IsFixedPoint(once) {
			t.Fatalf("IsFixedPoint(Redact(%q)) = false", in)
		}
		if strings.Count(in, "\n") != strings.Count(once, "\n") {
			t.Fatalf("Redact changed the line count of %q", in)
		}
	}
}

// TestRedactReachesAFixedPoint covers input where one pass of the rules is not
// enough: masking an inner URL credential completes an outer one.
func TestRedactReachesAFixedPoint(t *testing.T) {
	if got := Redact("://0:://0:0@@"); got != Marker {
		t.Fatalf("Redact(%q) = %q, want %q", "://0:://0:0@@", got, Marker)
	}
	if got := apply("://0:://0:0@@"); got != "://0:"+Marker+"@" {
		t.Fatalf("one pass = %q; the regression case no longer needs a second pass", got)
	}
	nested := func(levels int) string {
		return strings.Repeat("://0:", levels) + "0@" + strings.Repeat("@", levels-1)
	}
	// Within the pass budget, only the credential is masked.
	if got := Redact("keep\n" + nested(maxPasses-1)); got != "keep\n"+Marker {
		t.Fatalf("nested within budget: %q", got)
	}
	// Beyond it, the whole text is masked, line count kept, and the result is a
	// fixed point.
	in := "keep\n" + nested(maxPasses+4) + "\ntail"
	got := Redact(in)
	if got != Marker+"\n\n" {
		t.Fatalf("nested beyond budget: %q", got)
	}
	if Redact(got) != got || !IsFixedPoint(got) {
		t.Fatal("the fallback is not a fixed point")
	}
	// Deeply nested input costs a bounded number of passes, not one per level.
	deep := nested(50000)
	if out := Redact(deep); out != Marker {
		t.Fatalf("deeply nested input: %q", out[:min(len(out), 40)])
	}
}

func TestIsFixedPointMatchesRedact(t *testing.T) {
	for _, in := range redactionCorpus() {
		if got, want := IsFixedPoint(in), Redact(in) == in; got != want {
			t.Fatalf("IsFixedPoint(%q) = %v, Redact(s) == s is %v", in, got, want)
		}
	}
}

// TestRedactJSONFixedPoint shows why stored structured output must be checked
// for the fixed point: redacting a JSON document with a secret-shaped value can
// break its syntax, so such a document is not a fixed point and a consumer that
// requires one rejects it rather than storing something Sanitize would alter.
func TestRedactJSONFixedPoint(t *testing.T) {
	doc := `{"testResults":[{"assertionResults":[{"title":"password=hunter2","status":"passed"}]}]}`
	if IsFixedPoint(doc) {
		t.Fatal("a JSON document carrying a secret-shaped title must not be a fixed point")
	}
	if strings.Contains(Redact(doc), "hunter2") {
		t.Fatal("secret-shaped value leaked")
	}
	clean := map[string]any{"title": "Discount(5,33)", "status": "passed", "values": []string{"4", "3"}}
	data, err := json.Marshal(clean)
	if err != nil {
		t.Fatal(err)
	}
	if !IsFixedPoint(string(data)) {
		t.Fatalf("an ordinary JSON document must be a fixed point: %s", data)
	}
}

func FuzzRedactIdempotent(f *testing.F) {
	for _, seed := range redactionCorpus()[:64] {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, in string) {
		once := Redact(in)
		if Redact(once) != once {
			t.Fatalf("Redact is not idempotent for %q", in)
		}
		if strings.Count(in, "\n") != strings.Count(once, "\n") {
			t.Fatalf("Redact changed the line count of %q", in)
		}
	})
}

func TestTruncateUTF8(t *testing.T) {
	cases := []struct {
		in    string
		limit int
		want  string
	}{
		{"hello", 10, "hello"},
		{"hello", 5, "hello"},
		{"hello", 3, "hel"},
		{"hello", 0, ""},
		{"hello", -1, ""},
		{"", 0, ""},
		{"héllo", 2, "h"},          // é is two bytes; never split
		{"héllo", 3, "hé"},         // exact boundary
		{"日本語", 4, "日"},            // three-byte runes
		{"日本語", 6, "日本"},           // exact boundary
		{"a\xffb", 10, "a\uFFFDb"}, // fits: invalid bytes replaced
		{"a\xffbcdef", 3, "a"},     // cut: shortened until valid
	}
	for _, tc := range cases {
		got := TruncateUTF8(tc.in, tc.limit)
		if got != tc.want {
			t.Errorf("TruncateUTF8(%q, %d) = %q, want %q", tc.in, tc.limit, got, tc.want)
		}
		if !utf8.ValidString(got) {
			t.Errorf("TruncateUTF8(%q, %d) returned invalid UTF-8", tc.in, tc.limit)
		}
		if tc.limit >= 0 && len(got) > tc.limit && len(tc.in) > tc.limit {
			t.Errorf("TruncateUTF8(%q, %d) exceeded the limit", tc.in, tc.limit)
		}
	}
}
