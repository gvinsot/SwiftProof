package dockerutil

import (
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

const imageID = "sha256:a688600ca24f8a4d3ca77f95b0dd40704a9fc787c826660eb7ba0b641b8b175d"

// fakeRunner returns canned output and records the argv and limit it received.
type fakeRunner struct {
	stdout, stderr string
	err            error
	args           []string
	limit          int
	calls          int
}

func (f *fakeRunner) run(_ context.Context, args []string, limit int) ([]byte, []byte, error) {
	f.calls++
	f.args, f.limit = append([]string(nil), args...), limit
	return []byte(f.stdout), []byte(f.stderr), f.err
}

func TestValidImageID(t *testing.T) {
	for _, id := range []string{imageID, "sha256:" + strings.Repeat("0", 64)} {
		if !ValidImageID(id) {
			t.Errorf("refused %q", id)
		}
	}
	for _, id := range []string{"", "sha256:", imageID[:70], imageID + "0", strings.ToUpper(imageID), "sha512:" + strings.Repeat("0", 64), "golang:1.26-bookworm", " " + imageID, imageID + "\n", "sha256:" + strings.Repeat("g", 64)} {
		if ValidImageID(id) {
			t.Errorf("accepted %q", id)
		}
	}
}

func TestInspectImageParsesDockerJSON(t *testing.T) {
	f := &fakeRunner{stdout: `{"Id":"` + imageID + `","RepoTags":["golang:1.26-bookworm"],"Os":"linux","Architecture":"amd64","Size":123456,"Config":{"Labels":{"org.swiftproof.prepare.key":"abc"},"Env":["PATH=/usr/bin","GOLANG_VERSION=1.26"]},"RootFS":{"Type":"layers","Layers":["sha256:1","sha256:2"]}}` + "\n"}
	img, found, err := InspectImage(context.Background(), f.run, "golang:1.26-bookworm")
	if err != nil || !found {
		t.Fatalf("found=%v err=%v", found, err)
	}
	want := Image{ID: imageID, OS: "linux", Architecture: "amd64", Size: 123456, Labels: map[string]string{"org.swiftproof.prepare.key": "abc"}, Layers: []string{"sha256:1", "sha256:2"}, Env: []string{"PATH=/usr/bin", "GOLANG_VERSION=1.26"}}
	if !reflect.DeepEqual(img, want) {
		t.Fatalf("got %+v\nwant %+v", img, want)
	}
	if !reflect.DeepEqual(f.args, []string{"image", "inspect", "--format", "{{json .}}", "golang:1.26-bookworm"}) || f.limit != 4<<20 {
		t.Fatalf("argv %q limit %d", f.args, f.limit)
	}
	// An image without labels or layers still yields a usable, non-nil label map.
	f.stdout = `{"Id":"` + imageID + `","Os":"linux","Architecture":"arm64","Size":1,"Config":{"Labels":null,"Env":null}}`
	img, found, err = InspectImage(context.Background(), f.run, imageID)
	if err != nil || !found || img.Labels == nil || len(img.Labels) != 0 || img.Layers != nil || img.Env != nil {
		t.Fatalf("minimal image: %+v %v %v", img, found, err)
	}
}

func TestInspectImageNotFoundAndFailures(t *testing.T) {
	ctx := context.Background()
	for _, stderr := range []string{"Error: No such image: missing:tag", "Error response from daemon: no such image: missing:tag: No such image", "error: NO SUCH IMAGE"} {
		f := &fakeRunner{stderr: stderr, err: errors.New("exit status 1")}
		img, found, err := InspectImage(ctx, f.run, "missing:tag")
		if err != nil || found || img.ID != "" {
			t.Errorf("%q: found=%v err=%v", stderr, found, err)
		}
	}
	for name, f := range map[string]*fakeRunner{
		"daemon_down":   {stderr: "Cannot connect to the Docker daemon", err: errors.New("exit status 1")},
		"not_json":      {stdout: "sha256:abc"},
		"two_values":    {stdout: `{"Id":"` + imageID + `"} {"Id":"` + imageID + `"}`},
		"array":         {stdout: `[{"Id":"` + imageID + `"}]`},
		"short_id":      {stdout: `{"Id":"sha256:abc"}`},
		"missing_id":    {stdout: `{"Os":"linux"}`},
		"negative_size": {stdout: `{"Id":"` + imageID + `","Size":-1}`},
		"output_limit":  {err: ErrOutputLimit},
	} {
		t.Run(name, func(t *testing.T) {
			if _, found, err := InspectImage(ctx, f.run, "golang:1.26-bookworm"); err == nil || found {
				t.Fatalf("found=%v err=%v", found, err)
			}
		})
	}
	for _, ref := range []string{"", "-v", "--format=x", "image name", "image\n", "image\x00", strings.Repeat("a", 513)} {
		f := &fakeRunner{}
		if _, _, err := InspectImage(ctx, f.run, ref); err == nil || f.calls != 0 {
			t.Errorf("reference %q reached docker (calls=%d err=%v)", ref, f.calls, err)
		}
	}
	// A cancelled context never turns into "not found".
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	f := &fakeRunner{stderr: "No such image", err: context.Canceled}
	if _, found, err := InspectImage(cancelled, f.run, "x"); err == nil || found {
		t.Fatalf("cancelled inspect: found=%v err=%v", found, err)
	}
}

func TestServerInfo(t *testing.T) {
	ctx := context.Background()
	f := &fakeRunner{stdout: `{"ID":"x","ServerVersion":"28.4.0","OSType":"linux","Architecture":"x86_64","NCPU":8,"MemTotal":32365068288,"Plugins":{}}` + "\n"}
	info, err := ServerInfo(ctx, f.run)
	if err != nil {
		t.Fatal(err)
	}
	if info != (Info{ServerVersion: "28.4.0", OSType: "linux", Architecture: "x86_64", NCPU: 8, MemTotal: 32365068288}) {
		t.Fatalf("got %+v", info)
	}
	if !reflect.DeepEqual(f.args, []string{"info", "--format", "{{json .}}"}) || f.limit != 4<<20 {
		t.Fatalf("argv %q limit %d", f.args, f.limit)
	}
	for name, f := range map[string]*fakeRunner{
		"server_errors":  {stdout: `{"ServerVersion":"","ServerErrors":["Cannot connect to the Docker daemon"]}`},
		"exit_status":    {stdout: `{"ServerVersion":"28.4.0"}`, stderr: "boom", err: errors.New("exit status 1")},
		"no_version":     {stdout: `{"NCPU":2}`},
		"negative":       {stdout: `{"ServerVersion":"28.4.0","NCPU":-1}`},
		"malformed":      {stdout: `{"ServerVersion":`},
		"trailing_value": {stdout: `{"ServerVersion":"28.4.0"} 1`},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ServerInfo(ctx, f.run); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestLimitWriter(t *testing.T) {
	w := &limitWriter{limit: 4}
	if n, err := w.Write([]byte("abc")); n != 3 || err != nil {
		t.Fatal(n, err)
	}
	if _, err := w.Write([]byte("de")); err == nil || !w.exceeded {
		t.Fatal("stdout overflow was not an error")
	}
	e := &limitWriter{limit: 4, drop: true}
	if n, err := e.Write([]byte("abcdef")); n != 6 || err != nil || string(e.Bytes()) != "abcd" {
		t.Fatalf("stderr overflow: n=%d err=%v kept=%q", n, err, e.Bytes())
	}
}

func TestDefaultRunnerRefusesInteractiveFlags(t *testing.T) {
	for _, flag := range []string{"-i", "-t", "-it", "--interactive", "--tty"} {
		if _, _, err := DefaultRunner(context.Background(), []string{"run", flag, "x"}, 10); err == nil {
			t.Errorf("DefaultRunner accepted %s", flag)
		}
	}
}

// TestDockerInspectAndInfo runs the real docker CLI; it starts no container.
func TestDockerInspectAndInfo(t *testing.T) {
	image := os.Getenv("SWIFTPROOF_TEST_DOCKER_IMAGE")
	if image == "" {
		t.Skip("set SWIFTPROOF_TEST_DOCKER_IMAGE to a preloaded image")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	img, found, err := InspectImage(ctx, DefaultRunner, image)
	if err != nil || !found || !ValidImageID(img.ID) || img.OS == "" || img.Size <= 0 || len(img.Layers) == 0 {
		t.Fatalf("inspect %s: %+v found=%v err=%v", image, img, found, err)
	}
	byID, found, err := InspectImage(ctx, DefaultRunner, img.ID)
	if err != nil || !found || byID.ID != img.ID {
		t.Fatalf("inspect by ID: %+v found=%v err=%v", byID, found, err)
	}
	_, found, err = InspectImage(ctx, DefaultRunner, "swiftproof-dockerutil-absent-image:never-built")
	if err != nil || found {
		t.Fatalf("absent image: found=%v err=%v", found, err)
	}
	info, err := ServerInfo(ctx, DefaultRunner)
	if err != nil || info.ServerVersion == "" || info.NCPU < 1 || info.MemTotal <= 0 || info.OSType == "" {
		t.Fatalf("docker info: %+v %v", info, err)
	}
	if _, _, err := DefaultRunner(ctx, []string{"info", "--format", "{{json .}}"}, 16); !errors.Is(err, ErrOutputLimit) {
		t.Fatalf("stdout limit not enforced: %v", err)
	}
}
