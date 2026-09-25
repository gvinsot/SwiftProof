// Command build produces portable SwiftProof binaries, archives, and checksums.
// Run from the app directory of the repository: go run ./tools/build
package main

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
)

// The license covers the whole repository and lives at its root.
const licensePath = "../LICENSE"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	err := run(ctx)
	stop()
	if err != nil {
		fmt.Fprintln(os.Stderr, "build:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	out := flag.String("out", "dist", "directory for binaries, archives and SHA256SUMS")
	version := flag.String("version", "dev", "version embedded in binaries and archive names")
	targets := flag.String("targets", "windows/amd64,linux/amd64,linux/arm64", "comma-separated OS/architecture targets")
	flag.Parse()
	if flag.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments")
	}
	if !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$`).MatchString(*version) {
		return fmt.Errorf("version must be a portable name of 1..128 characters")
	}
	var selected [][2]string
	seen := map[string]bool{}
	for _, target := range strings.Split(*targets, ",") {
		target = strings.TrimSpace(target)
		osName, arch, ok := strings.Cut(target, "/")
		if !ok || (osName != "windows" && osName != "linux" && osName != "darwin") || (arch != "amd64" && arch != "arm64") {
			return fmt.Errorf("unsupported target %q; use windows, linux or darwin with amd64 or arm64", target)
		}
		if !seen[target] {
			selected = append(selected, [2]string{osName, arch})
			seen[target] = true
		}
	}
	for _, path := range []string{"go.mod", "cmd/swiftproof/main.go", "README.md", licensePath} {
		if _, err := os.Stat(path); err != nil {
			return fmt.Errorf("run from the app directory of the SwiftProof repository: %w", err)
		}
	}
	dir, err := filepath.Abs(*out)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	goBinary := filepath.Join(runtime.GOROOT(), "bin", "go")
	if runtime.GOOS == "windows" {
		goBinary += ".exe"
	}
	if _, err := os.Stat(goBinary); err != nil {
		goBinary, err = exec.LookPath("go")
		if err != nil {
			return fmt.Errorf("Go compiler not found: %w", err)
		}
	}
	var sums []string
	for _, target := range selected {
		if err := ctx.Err(); err != nil {
			return err
		}
		archive, err := build(ctx, goBinary, dir, *version, target[0], target[1])
		if err != nil {
			return err
		}
		f, err := os.Open(archive)
		if err != nil {
			return err
		}
		digest := sha256.New()
		_, copyErr := io.Copy(digest, f)
		closeErr := f.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
		sums = append(sums, fmt.Sprintf("%x  %s", digest.Sum(nil), filepath.Base(archive)))
		fmt.Println(archive)
	}
	sort.Strings(sums)
	if err := os.WriteFile(filepath.Join(dir, "SHA256SUMS"), []byte(strings.Join(sums, "\n")+"\n"), 0644); err != nil {
		return err
	}
	fmt.Println(filepath.Join(dir, "SHA256SUMS"))
	return nil
}

func build(ctx context.Context, goBinary, out, version, osName, arch string) (string, error) {
	target := osName + "-" + arch
	name := "swiftproof"
	if osName == "windows" {
		name += ".exe"
	}
	dir := filepath.Join(out, target)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", err
	}
	temp, err := os.MkdirTemp(out, ".swiftproof-build-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(temp)
	binary := filepath.Join(temp, name)
	fmt.Fprintf(os.Stderr, "Building %s...\n", target)
	cmd := exec.CommandContext(ctx, goBinary, "build", "-trimpath", "-buildvcs=false", "-ldflags=-s -w -X main.version="+version, "-o", binary, "./cmd/swiftproof")
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		switch strings.ToUpper(key) {
		case "GOOS", "GOARCH", "CGO_ENABLED":
			continue
		}
		cmd.Env = append(cmd.Env, entry)
	}
	cmd.Env = append(cmd.Env, "GOOS="+osName, "GOARCH="+arch, "CGO_ENABLED=0")
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%s: %w", target, err)
	}
	destination := filepath.Join(dir, name)
	if err := os.Rename(binary, destination); err != nil {
		return "", err
	}
	prefix := "swiftproof-" + version + "-" + target
	extension := ".tar.gz"
	if osName == "windows" {
		extension = ".zip"
	}
	archive := filepath.Join(temp, prefix+extension)
	files := []entry{{destination, name, 0755}, {licensePath, "LICENSE", 0644}, {"README.md", "README.md", 0644}}
	if err := pack(archive, prefix, files, osName == "windows"); err != nil {
		return "", err
	}
	archivePath := filepath.Join(out, prefix+extension)
	if err := os.Rename(archive, archivePath); err != nil {
		return "", err
	}
	return archivePath, nil
}

type entry struct {
	source, name string
	mode         int64
}

func pack(path, prefix string, files []entry, windows bool) (err error) {
	out, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := out.Close(); err == nil {
			err = closeErr
		}
	}()
	var zipWriter *zip.Writer
	var tarWriter *tar.Writer
	if windows {
		zipWriter = zip.NewWriter(out)
		defer func() {
			if closeErr := zipWriter.Close(); err == nil {
				err = closeErr
			}
		}()
	} else {
		compressed := gzip.NewWriter(out)
		defer func() {
			if closeErr := compressed.Close(); err == nil {
				err = closeErr
			}
		}()
		tarWriter = tar.NewWriter(compressed)
		defer func() {
			if closeErr := tarWriter.Close(); err == nil {
				err = closeErr
			}
		}()
	}
	for _, item := range files {
		f, err := os.Open(item.source)
		if err != nil {
			return err
		}
		info, err := f.Stat()
		if err != nil {
			f.Close()
			return err
		}
		var writer io.Writer = tarWriter
		if windows {
			h := &zip.FileHeader{Name: prefix + "/" + item.name, Method: zip.Deflate}
			h.SetMode(os.FileMode(item.mode))
			writer, err = zipWriter.CreateHeader(h)
		} else {
			err = tarWriter.WriteHeader(&tar.Header{Name: prefix + "/" + item.name, Mode: item.mode, Size: info.Size()})
		}
		if err != nil {
			f.Close()
			return err
		}
		_, copyErr := io.Copy(writer, f)
		closeErr := f.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
	}
	return nil
}
