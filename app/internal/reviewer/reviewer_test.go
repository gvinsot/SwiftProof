package reviewer

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gvinsot/SwiftProof/app/internal/model"
	reports "github.com/gvinsot/SwiftProof/app/internal/report"
)

type fakeHarness struct{ calls []string }

func (f *fakeHarness) Call(_ context.Context, name string, _ json.RawMessage) (json.RawMessage, error) {
	f.calls = append(f.calls, name)
	return json.RawMessage(`{"content":"observed"}`), nil
}

func complete(w http.ResponseWriter, calls ...toolCall) {
	m := message{Role: "assistant", Content: "Done", ToolCalls: calls}
	_ = json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": m, "finish_reason": "stop"}}})
}

func call(id, name, args string) toolCall {
	c := toolCall{ID: id, Type: "function"}
	c.Function.Name = name
	c.Function.Arguments = args
	return c
}

func TestToolLoopDoesNotTrustFabricatedProof(t *testing.T) {
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.URL.Path != "/v1/chat/completions" {
			t.Errorf("wrong path %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer api-secret" {
			t.Error("authorization missing")
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if body["max_completion_tokens"] != float64(4096) {
			t.Error("missing token bound")
		}
		switch requests {
		case 1:
			complete(w, call("a", "read_file", `{"path":"main.go"}`))
		case 2:
			complete(w, call("b", "submit_hypothesis", `{"title":"Claim","severity":"high","status":"REPRODUCED","rationale":"Model assertion","evidence_ids":["invented"],"path":"main.go","line":1}`))
		default:
			complete(w)
		}
	}))
	defer server.Close()
	r := &model.Report{}
	h := &fakeHarness{}
	if err := Run(context.Background(), Options{Endpoint: server.URL + "/v1", Model: "test", APIKey: "api-secret"}, r, h); err != nil {
		t.Fatal(err)
	}
	if requests != 3 || len(h.calls) != 1 || h.calls[0] != "read_file" || len(r.Hypotheses) != 1 {
		t.Fatalf("unexpected loop: requests %d calls %v hypotheses %v", requests, h.calls, r.Hypotheses)
	}
	reports.Finalize(r, true)
	if r.Hypotheses[0].Status != "UNVERIFIED" || len(r.ReproducedIssues) != 0 {
		t.Fatal("model assertion became proof")
	}
}

func TestEndpointRejectsUnsafeConfiguration(t *testing.T) {
	for _, endpoint := range []string{"http://example.com/v1", "file:///tmp/provider", "https://user:password@example.com/v1", "https://example.com/v1?key=secret", "https://example.com/v1#fragment"} {
		t.Run(endpoint, func(t *testing.T) {
			if err := Validate(Options{Endpoint: endpoint, Model: "test"}); err == nil {
				t.Fatal("unsafe endpoint accepted")
			}
		})
	}
	_, endpoint, err := normalize(Options{Endpoint: "http://localhost:1234/v1", Model: "test"})
	if err != nil || endpoint != "http://127.0.0.1:1234/v1/chat/completions" {
		t.Fatalf("local endpoint %s %v", endpoint, err)
	}
}

func TestRedirectDoesNotForwardCredentials(t *testing.T) {
	var reached atomic.Bool
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached.Store(true); complete(w) }))
	defer destination.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL, http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	err := Run(context.Background(), Options{Endpoint: server.URL, Model: "test", APIKey: "top-secret"}, &model.Report{}, &fakeHarness{})
	if err == nil || reached.Load() {
		t.Fatal("redirect followed")
	}
	if strings.Contains(err.Error(), "top-secret") {
		t.Fatal("error leaked API key")
	}
}

func TestInitialPromptMasksSensitiveFilesAndKnownCredential(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		encoded, _ := json.Marshal(body)
		for _, secret := range []string{"plain-sensitive-value", "specific-api-key"} {
			if strings.Contains(string(encoded), secret) {
				t.Errorf("leaked %s", secret)
			}
		}
		complete(w)
	}))
	defer server.Close()
	r := &model.Report{Intent: "specific-api-key", Change: model.Change{Files: []model.ChangedFile{{Path: ".env", Hunks: []model.Hunk{{Lines: []model.DiffLine{{Content: "plain-sensitive-value"}}}}}}}}
	if err := Run(context.Background(), Options{Endpoint: server.URL, Model: "test", APIKey: "specific-api-key"}, r, &fakeHarness{}); err != nil {
		t.Fatal(err)
	}
}

func TestBudgetsFailClosed(t *testing.T) {
	t.Run("iteration", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { complete(w, call("a", "run_build", `{}`)) }))
		defer server.Close()
		r := &model.Report{}
		h := &fakeHarness{}
		if err := Run(context.Background(), Options{Endpoint: server.URL, Model: "test", MaxIterations: 1}, r, h); err != nil {
			t.Fatal(err)
		}
		if len(r.Unverified) == 0 || len(h.calls) != 1 {
			t.Fatal("budget exhaustion not recorded")
		}
	})
	t.Run("input", func(t *testing.T) {
		var reached bool
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached = true; complete(w) }))
		defer server.Close()
		r := &model.Report{Intent: strings.Repeat("x", 4000)}
		if err := Run(context.Background(), Options{Endpoint: server.URL, Model: "test", MaxInputBytes: 1024}, r, &fakeHarness{}); err != nil {
			t.Fatal(err)
		}
		if reached || len(r.Unverified) == 0 {
			t.Fatal("oversized request sent")
		}
	})
	t.Run("timeout", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-r.Context().Done():
			case <-time.After(100 * time.Millisecond):
			}
		}))
		defer server.Close()
		err := Run(context.Background(), Options{Endpoint: server.URL, Model: "test", Timeout: 20 * time.Millisecond}, &model.Report{}, &fakeHarness{})
		if err == nil {
			t.Fatal("timeout ignored")
		}
	})
}

func TestUnknownToolNeverReachesHarness(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if requests == 1 {
			complete(w, call("x", "shell", `{"cmd":"bad"}`))
			return
		}
		complete(w)
	}))
	defer server.Close()
	h := &fakeHarness{}
	if err := Run(context.Background(), Options{Endpoint: server.URL, Model: "test"}, &model.Report{}, h); err != nil {
		t.Fatal(err)
	}
	if len(h.calls) != 0 {
		t.Fatalf("unavailable tool called: %v", h.calls)
	}
}

func TestHTTPErrorDoesNotEchoProviderBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, "api-secret provider sensitive body")
	}))
	defer server.Close()
	err := Run(context.Background(), Options{Endpoint: server.URL, Model: "test", APIKey: "api-secret"}, &model.Report{}, &fakeHarness{})
	if err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatalf("bad error: %v", err)
	}
}
