package harness

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/gvinsot/SwiftProof/app/internal/model"
)

func TestStageEphemeralCreatesAndRemovesDeepestFirst(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "existing"), 0755); err != nil {
		t.Fatal(err)
	}
	cleanup, err := stageEphemeral(root, "existing/new/deeper/x_test.go", "package x\n")
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(root, "existing", "new", "deeper", "x_test.go"))
	if err != nil || string(b) != "package x\n" {
		t.Fatalf("staged content %q %v", b, err)
	}
	cleanup()
	cleanup() // idempotent
	if _, err := os.Stat(filepath.Join(root, "existing", "new")); !os.IsNotExist(err) {
		t.Fatal("created directories were not removed")
	}
	if _, err := os.Stat(filepath.Join(root, "existing")); err != nil {
		t.Fatal("a pre-existing directory was removed")
	}
	// A directory the caller did not create is kept even if it is emptied.
	cleanup, err = stageEphemeral(root, "top_test.go", "x")
	if err != nil {
		t.Fatal(err)
	}
	cleanup()
	if entries, _ := os.ReadDir(root); len(entries) != 1 || entries[0].Name() != "existing" {
		t.Fatalf("root after cleanup: %v", entries)
	}
}

func TestStageEphemeralRefusesUnsafeOrExistingPaths(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "main.go"), []byte("package main\n"), 0644); err != nil {
		t.Fatal(err)
	}
	for _, rel := range []string{"main.go", "../escape_test.go", "/abs_test.go", ".env", "a/.aws/credentials", `a\b_test.go`, "", "C:/x_test.go"} {
		cleanup, err := stageEphemeral(root, rel, "x")
		if err == nil {
			t.Errorf("staged %q", rel)
		}
		if cleanup == nil {
			t.Fatalf("nil cleanup for %q", rel)
		}
		cleanup()
	}
	if b, _ := os.ReadFile(filepath.Join(root, "main.go")); string(b) != "package main\n" {
		t.Fatal("an existing file was overwritten")
	}
	if err := os.Symlink(t.TempDir(), filepath.Join(root, "link")); err == nil {
		if _, err := stageEphemeral(root, "link/x_test.go", "x"); err == nil {
			t.Error("staged through a symlink")
		}
	}
	if _, err := stageEphemeral("", "x_test.go", "x"); err == nil {
		t.Error("staged without a root")
	}
	if entries, _ := os.ReadDir(root); len(entries) > 2 {
		t.Fatalf("refused staging left files behind: %v", entries)
	}
}

func TestPrivateCopyIsIsolatedAndRemovable(t *testing.T) {
	h := fixture(t)
	h.mu.Lock()
	dir, cleanup, err := h.privateCopy("hybrid-")
	h.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(dir) != h.root || !strings.HasPrefix(filepath.Base(dir), "hybrid-") {
		t.Fatalf("private copy at %s, want a hybrid- directory under %s", dir, h.root)
	}
	b, err := os.ReadFile(filepath.Join(dir, "pkg", "main.go"))
	if err != nil || !strings.Contains(string(b), "return 42") {
		t.Fatalf("copy content %q %v", b, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "pkg", "main.go"), []byte("mutated"), 0644); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(h.candidate, "pkg", "main.go")); string(b) == "mutated" {
		t.Fatal("the private copy aliases the candidate snapshot")
	}
	cleanup()
	cleanup()
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("cleanup kept the private copy")
	}
	h.mu.Lock()
	second, cleanup2, err := h.privateCopy("mutation-")
	h.mu.Unlock()
	if err != nil || second == dir {
		t.Fatalf("second copy %s %v", second, err)
	}
	defer cleanup2()
	for _, prefix := range []string{"", "../x", "a/b", `a\b`, "c:"} {
		h.mu.Lock()
		_, c, err := h.privateCopy(prefix)
		h.mu.Unlock()
		if err == nil || c == nil {
			t.Errorf("prefix %q accepted", prefix)
		}
	}
	h.Close()
	if _, _, err := h.privateCopy("late-"); err == nil {
		t.Fatal("a closed harness made a private copy")
	}
}

func TestAppendEvidenceAssignsDenseIDsAndCopies(t *testing.T) {
	h := fixture(t)
	names, symbols := []string{"TestA"}, []string{"Total"}
	h.mu.Lock()
	first := h.appendEvidence(model.Evidence{ID: "forged", Kind: model.EvidenceIntentTest, TestNames: names, ReferencedSymbols: symbols, Status: model.StatusUnverified})
	second := h.appendEvidence(model.Evidence{Kind: model.EvidenceSourceObservation, Status: model.StatusObserved})
	h.mu.Unlock()
	if first.ID != "evidence-1" || second.ID != "evidence-2" {
		t.Fatalf("IDs %s %s", first.ID, second.ID)
	}
	names[0], symbols[0] = "changed", "changed"
	first.TestNames[0] = "changed too"
	stored := h.Evidence()
	if stored[0].TestNames[0] != "TestA" || stored[0].ReferencedSymbols[0] != "Total" {
		t.Fatalf("evidence shares slices with its caller: %+v", stored[0])
	}
	stored[0].ReferencedSymbols[0] = "x"
	if h.Evidence()[0].ReferencedSymbols[0] != "Total" {
		t.Fatal("Evidence() shares ReferencedSymbols")
	}
	// read_file source observations use the same numbering.
	out := call(t, h, "read_file", map[string]any{"path": "pkg/main.go"})
	if !strings.Contains(string(out), `"evidence_id":"evidence-3"`) {
		t.Fatalf("source observation %s", out)
	}
}

func TestReplaceCheckByIDInEitherLedger(t *testing.T) {
	h := fixture(t)
	h.mu.Lock()
	defer h.mu.Unlock()
	h.checks = []model.Check{{ID: "check-1", Status: "PASS"}, {ID: "check-2", Status: "PASS"}}
	h.mutationChecks = []model.Check{{ID: "mutation-check-1", Status: "PASS"}}
	h.replaceCheck(model.Check{ID: "check-1", Status: "ERROR", Results: "abc"})
	h.replaceCheck(model.Check{ID: "mutation-check-1", Status: "FAIL", Results: "de"})
	h.replaceCheck(model.Check{ID: "check-9", Status: "FAIL"})
	h.replaceCheck(model.Check{ID: "other-1", Status: "FAIL"})
	h.replaceCheck(model.Check{ID: "mutation-check-7", Status: "FAIL"})
	if h.checks[0].Status != "ERROR" || h.checks[1].Status != "PASS" || len(h.checks) != 2 {
		t.Fatalf("main ledger %+v", h.checks)
	}
	if h.mutationChecks[0].Status != "FAIL" || len(h.mutationChecks) != 1 {
		t.Fatalf("mutation ledger %+v", h.mutationChecks)
	}
	if h.resultsBytes != 5 || h.resultsRemaining() != ResultsBudget-5 {
		t.Fatalf("results budget %d", h.resultsBytes)
	}
	h.replaceCheck(model.Check{ID: "check-1", Status: "ERROR"})
	if h.resultsBytes != 2 {
		t.Fatalf("results budget after shrinking %d", h.resultsBytes)
	}
}

func TestExportedPayloadLimitAndGoTemplate(t *testing.T) {
	for in, want := range map[int]int{256: 256 << 10, 64 << 10: 1 << 20, 4 << 20: 4 << 20} {
		if got := PayloadLimit(in); got != want {
			t.Errorf("PayloadLimit(%d) = %d, want %d", in, got, want)
		}
	}
	for _, cmd := range [][]string{{"go", "test", "{package}"}, {"go", "test", "-race", "{file}"}} {
		if !VerifiableGoTemplate(cmd) || VerifiableGoTemplate(cmd) != verifiableGoTemplate(cmd) {
			t.Errorf("refused %q", cmd)
		}
	}
	for _, cmd := range [][]string{{"go", "test", "./..."}, {"go", "test", "-exec=x", "{package}"}, {"sh", "-c", "{package}"}, {"go", "test", "{package}", "{file}"}} {
		if VerifiableGoTemplate(cmd) {
			t.Errorf("accepted %q", cmd)
		}
	}
	if ResultsBudget != 16<<20 {
		t.Fatal("ResultsBudget changed")
	}
	if !reflect.DeepEqual(copyChecks(nil), []model.Check(nil)) {
		t.Fatal("copyChecks(nil)")
	}
}
