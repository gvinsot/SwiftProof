package fsutil

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestSystemAlias(t *testing.T) {
	if runtime.GOOS == "darwin" && !IsSystemAlias("/var") {
		t.Fatal("macOS temporary-directory system alias must be allowed")
	}
	root := t.TempDir()
	if IsSystemAlias(root) {
		t.Fatal("ordinary directory is not a system alias")
	}
	link := filepath.Join(root, "var")
	if err := os.Symlink(root, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if IsSystemAlias(link) {
		t.Fatal("user-created symlink must not be trusted")
	}
}
