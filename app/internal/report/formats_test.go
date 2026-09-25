package report

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gvinsot/SwiftProof/app/internal/model"
)

func TestValidFormat(t *testing.T) {
	for format, want := range map[string]bool{
		FormatMarkdown: true, FormatJSON: true,
		"": false, "Markdown": false, "JSON": false, " json": false, "html": false,
		// F9 adds these; this build must refuse them.
		"sarif": false, "pr-comment": false,
	} {
		if ValidFormat(format) != want {
			t.Errorf("ValidFormat(%q) = %v", format, !want)
		}
	}
}

func TestRenderFormat(t *testing.T) {
	r := Sanitize(proofReport())
	for format, name := range map[string]string{FormatMarkdown: "CONFIDENCE_REPORT.md", FormatJSON: "confidence-report.json"} {
		got, data, err := renderFormat(format, r, writeOptions{})
		if err != nil || got != name || len(data) == 0 || data[len(data)-1] != '\n' {
			t.Errorf("%s: name %q, %d bytes, err %v", format, got, len(data), err)
		}
	}
	if _, _, err := renderFormat("sarif", r, writeOptions{}); err == nil {
		t.Fatal("unknown format rendered")
	}
}

// Options only affect formats that use them; nil options are ignored, and the
// default is Markdown plus JSON.
func TestWriteOptionsAndDefaults(t *testing.T) {
	r := proofReport()
	Finalize(r, true)
	plain, withURL := t.TempDir(), t.TempDir()
	if err := Write(plain, r, nil); err != nil {
		t.Fatal(err)
	}
	if err := Write(withURL, r, nil, WithReportURL("https://example.invalid/runs/1"), nil); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"CONFIDENCE_REPORT.md", "confidence-report.json"} {
		a, err := os.ReadFile(filepath.Join(plain, name))
		if err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(filepath.Join(withURL, name))
		if err != nil {
			t.Fatal(err)
		}
		if string(a) != string(b) {
			t.Errorf("%s depends on the report URL option", name)
		}
	}
	var o writeOptions
	WithReportURL("https://example.invalid/r")(&o)
	if o.reportURL != "https://example.invalid/r" {
		t.Fatalf("option not applied: %+v", o)
	}
	entries, err := os.ReadDir(plain)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("Write left %d entries (temporary files?)", len(entries))
	}
}

// Every format is validated before anything is rendered or written.
func TestWriteValidatesEveryFormatFirst(t *testing.T) {
	dir := t.TempDir()
	if err := Write(dir, &model.Report{}, []string{FormatMarkdown, FormatJSON, "sarif"}); err == nil {
		t.Fatal("expected an error for a format this build does not render")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("a rejected write left %d files", len(entries))
	}
}
