package server

import (
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/gvinsot/SwiftProof/hub/internal/analysis"
	"github.com/gvinsot/SwiftProof/hub/internal/store"
)

// maxHookBytes bounds a webhook delivery. A push payload lists the pushed
// commits; forges cap it well below this.
const maxHookBytes = 5 << 20

// handleWebhook receives a push delivery and schedules the analysis.
//
// The request is authenticated by the per-repository secret, never by a
// session: the forge is the caller. The routing key in the URL is random, so
// the endpoint cannot be enumerated, and the payload only decides which commit
// of that repository is analyzed.
func (s *Server) handleWebhook(w http.ResponseWriter, r *http.Request) {
	route, err := s.store.Hook(r.PathValue("hook"))
	if err != nil {
		// An unknown key and a wrong signature look the same from outside.
		http.Error(w, "unknown webhook", http.StatusNotFound)
		return
	}
	repo, err := s.store.Repo(route.UserKey, route.RepoKey)
	if err != nil || !repo.Monitored {
		http.Error(w, "unknown webhook", http.StatusNotFound)
		return
	}
	provider, err := s.accounts.Provider(repo.Provider)
	if err != nil {
		http.Error(w, "forge not configured", http.StatusNotFound)
		return
	}
	secret, err := s.keys.Open(repo.HookSecret)
	if err != nil || secret == "" {
		s.log.Error("webhook secret unreadable", "repo", repo.FullName)
		http.Error(w, "webhook is not usable", http.StatusInternalServerError)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxHookBytes))
	if err != nil {
		http.Error(w, "unreadable payload", http.StatusBadRequest)
		return
	}
	if err := provider.VerifyWebhook(r, body, secret); err != nil {
		s.log.Warn("webhook rejected", "repo", repo.FullName, "reason", err)
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return
	}
	if ping(r) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "pong"})
		return
	}
	if !isPush(r) {
		writeJSON(w, http.StatusAccepted, map[string]string{"status": "ignored"})
		return
	}
	push, err := provider.ParsePush(body)
	if err != nil {
		http.Error(w, "unreadable payload", http.StatusBadRequest)
		return
	}
	// The secret already proves the sender; matching the repository identity
	// makes sure a hook cannot be pointed at another entry of the same user.
	if push.RepoID != "" && repo.ID != "" && push.RepoID != repo.ID {
		s.log.Warn("webhook repository mismatch", "repo", repo.FullName, "payload", push.FullName)
		http.Error(w, "repository mismatch", http.StatusBadRequest)
		return
	}
	if !push.IsBranch || push.IsDeletion {
		writeJSON(w, http.StatusAccepted, map[string]string{"status": "ignored"})
		return
	}
	branch := strings.TrimPrefix(push.Ref, "refs/heads/")
	if s.cfg.DefaultBranchOnly && repo.DefaultBranch != "" && branch != repo.DefaultBranch {
		writeJSON(w, http.StatusAccepted, map[string]string{"status": "ignored"})
		return
	}
	job := analysis.Job{
		UserKey: route.UserKey, RepoKey: route.RepoKey, Commit: push.After, Before: push.Before,
		Ref: push.Ref, Message: push.Message, Author: push.Author, Trigger: analysis.TriggerPush,
	}
	if err := s.runner.Enqueue(job); err != nil {
		if errors.Is(err, analysis.ErrBusy) {
			// Forges retry a 503, which is exactly the behavior wanted here.
			http.Error(w, "busy", http.StatusServiceUnavailable)
			return
		}
		http.Error(w, "invalid push", http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "queued", "commit": push.After})
}

func ping(r *http.Request) bool {
	return r.Header.Get("X-GitHub-Event") == "ping"
}

func isPush(r *http.Request) bool {
	if r.Header.Get("X-GitHub-Event") == "push" {
		return true
	}
	event := r.Header.Get("X-Gitlab-Event")
	return event == "Push Hook" || event == "Tag Push Hook"
}

// hookRepo resolves a routing key to its repository, for the badge endpoint.
func (s *Server) hookRepo(hookKey string) (*store.Repo, bool) {
	route, err := s.store.Hook(hookKey)
	if err != nil {
		return nil, false
	}
	repo, err := s.store.Repo(route.UserKey, route.RepoKey)
	if err != nil {
		return nil, false
	}
	return repo, true
}
