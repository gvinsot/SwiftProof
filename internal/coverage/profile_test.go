package coverage

import (
	"errors"
	"strconv"
	"strings"
	"testing"
)

func TestParseGoProfileModes(t *testing.T) {
	for _, mode := range []string{"set", "count", "atomic"} {
		p, err := ParseGoProfile([]byte("mode: " + mode + "\nexample.com/m/a.go:1.1,2.2 1 0\n"))
		if err != nil {
			t.Fatalf("mode %s rejected: %v", mode, err)
		}
		if p.Mode != mode || len(p.Blocks) != 1 {
			t.Fatalf("mode %s parsed as %+v", mode, p)
		}
	}
	rejected := map[string]string{
		"unknown mode":    "mode: unknown\n",
		"empty":           "",
		"block row first": "example.com/m/a.go:1.1,2.2 1 0\n",
		"lcov":            "TN:\nSF:/workspace/a.go\nDA:1,1\nend_of_record\n",
		"cobertura":       "<?xml version=\"1.0\"?><coverage line-rate=\"0.5\"></coverage>",
	}
	for name, body := range rejected {
		if _, err := ParseGoProfile([]byte(body)); !errors.Is(err, ErrNotGo) {
			t.Fatalf("%s accepted as a Go profile: %v", name, err)
		}
	}
}

// A skipped row silently removes lines from the instrumented set, which renders
// downstream as "no executable code here" or as "not executed". Every malformed
// row therefore fails the whole profile and names its line.
func TestParseRejectsMalformedRowsLoudly(t *testing.T) {
	rows := []string{
		"example.com/m/a.go:1.1,2.2 1",
		"example.com/m/a.go:1.1,2.2 1 0 extra",
		"example.com/m/a.go 1 0",
		"example.com/m/a.go:1.1 1 0",
		"example.com/m/a.go:1.1,2.2 x 0",
		"example.com/m/a.go:1.1,2.2 1 y",
		"example.com/m/a.go:0.1,2.2 1 0",
		"example.com/m/a.go:5.1,2.2 1 0",
		"example.com/m/a.go:1.1,2.2 -1 0",
	}
	for _, row := range rows {
		_, err := ParseGoProfile([]byte("mode: count\n" + row + "\n"))
		if err == nil {
			t.Fatalf("malformed row accepted: %q", row)
		}
		if !strings.Contains(err.Error(), "could not be parsed at line 2") {
			t.Fatalf("row %q: error does not name the row: %v", row, err)
		}
	}
}

func TestParseBounds(t *testing.T) {
	var b strings.Builder
	b.WriteString("mode: count\n")
	for i := 1; i <= maxBlocks+1; i++ {
		n := strconv.Itoa(i)
		b.WriteString("example.com/m/a.go:" + n + ".1," + n + ".2 1 0\n")
	}
	if _, err := ParseGoProfile([]byte(b.String())); !errors.Is(err, ErrBlockLimit) {
		t.Fatalf("block bound not enforced: %v", err)
	}
	oversized := make([]byte, maxProfileBytes+1)
	if _, err := ParseGoProfile(oversized); !errors.Is(err, ErrBlockLimit) {
		t.Fatalf("size bound not enforced: %v", err)
	}
}

// The cover tool can emit the same range twice; summing is the only resolution
// that cannot turn an executed block into an unexecuted one.
func TestParseSumsDuplicateBlocks(t *testing.T) {
	p, err := ParseGoProfile([]byte("mode: count\nexample.com/m/a.go:1.1,2.2 1 0\nexample.com/m/a.go:1.1,2.2 1 3\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Blocks) != 1 || p.Blocks[0].Count != 3 {
		t.Fatalf("duplicate ranges not summed: %+v", p.Blocks)
	}
	if classify(p.Blocks, 1) != executed {
		t.Fatal("a range executed in one entry and not in a duplicate resolved as not executed")
	}
}
