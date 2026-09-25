package linter

import (
	"testing"

	"github.com/gvinsot/SwiftProof/app/internal/model"
)

func TestTokenDigestIgnoresLayoutAndComments(t *testing.T) {
	base := TokenDigest([]byte("package p\n\nfunc F(a int) int {\n\tb := a + 1\n\treturn b\n}\n"))
	if len(base) != 64 {
		t.Fatalf("digest %q is not a hex SHA-256", base)
	}
	for _, same := range []string{
		"package p\n\n// F adds one.\nfunc F(a int) int {\n\t/* sum */ b := a + 1 // inline\n\n\treturn b\n}\n",
		"package p\n\nfunc F(a   int)   int {\n        b := a+1\n        return b\n}",
	} {
		if got := TokenDigest([]byte(same)); got != base {
			t.Errorf("layout or comment change altered the digest:\n%s", same)
		}
	}
	for _, different := range []string{
		"package p\n\nfunc F(a int) int {\n\tb := a + 2\n\treturn b\n}\n",
		"package p\n\nfunc F(a int) int {\n\tb := a - 1\n\treturn b\n}\n",
		"package p\n\nfunc F(a int) int {\n\tb := a + 1\n\treturn a\n}\n",
		"package p\n\nfunc F(a int) string {\n\tb := a + 1\n\treturn b\n}\n",
		"package p\n\nfunc F(a int) int {\n\tb := \"a + 1\"\n\treturn b\n}\n",
	} {
		if got := TokenDigest([]byte(different)); got == base {
			t.Errorf("token change kept the digest:\n%s", different)
		}
	}
	if TokenDigest(nil) != TokenDigest([]byte("")) || TokenDigest(nil) == base {
		t.Error("empty source digest is inconsistent")
	}
}

func TestFirstChangedLineMatchesSignalAnchor(t *testing.T) {
	for _, tc := range []struct {
		file model.ChangedFile
		line int
		side string
	}{
		{model.ChangedFile{Path: "a.go", Hunks: []model.Hunk{{Lines: []model.DiffLine{{Kind: "context", OldLine: 1, NewLine: 1}, {Kind: "add", NewLine: 7}}}}}, 7, "new"},
		{model.ChangedFile{Path: "a.go", Hunks: []model.Hunk{{Lines: []model.DiffLine{{Kind: "delete", OldLine: 4}, {Kind: "add", NewLine: 4}}}}}, 4, "old"},
		{model.ChangedFile{Path: "a.go", Status: "D"}, 1, "old"},
		{model.ChangedFile{Path: "a.go", Status: "M"}, 1, "new"},
	} {
		line, side := FirstChangedLine(tc.file)
		if line != tc.line || side != tc.side {
			t.Errorf("FirstChangedLine(%+v) = %d %s, want %d %s", tc.file, line, side, tc.line, tc.side)
		}
		if l, s := firstChangedLine(tc.file); l != line || s != side {
			t.Errorf("exported wrapper disagrees with firstChangedLine: %d %s vs %d %s", line, side, l, s)
		}
	}
}
