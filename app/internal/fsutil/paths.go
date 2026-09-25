// Package fsutil contains filesystem checks shared by export and report writing.
package fsutil

import (
	"os"
	"path/filepath"
	"runtime"
)

// IsSystemAlias recognizes macOS's root-level aliases into /private. These
// system paths contain the default temporary directory; arbitrary symlinks,
// including similarly named paths below a user directory, remain forbidden.
func IsSystemAlias(path string) bool {
	if runtime.GOOS != "darwin" || (path != "/var" && path != "/tmp" && path != "/etc") {
		return false
	}
	target, err := os.Readlink(path)
	if err != nil {
		return false
	}
	if !filepath.IsAbs(target) {
		target = filepath.Join(filepath.Dir(path), target)
	}
	return filepath.Clean(target) == "/private"+path
}
