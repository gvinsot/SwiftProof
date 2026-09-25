package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/gvinsot/SwiftProof/hub/internal/analysis"
	"github.com/gvinsot/SwiftProof/hub/internal/forge"
	"github.com/gvinsot/SwiftProof/hub/internal/report"
	"github.com/gvinsot/SwiftProof/hub/internal/secrets"
	"github.com/gvinsot/SwiftProof/hub/internal/store"
)

// policyProbes bounds how many repositories are inspected in parallel during a
// sync: enough to keep a few hundred repositories quick, low enough to stay
// friendly with forge rate limits.
const policyProbes = 8

func (s *Server) handleRepos(w http.ResponseWriter, r *http.Request) {
	sess, _, ok := s.require(w, r)
	if !ok {
		return
	}
	repos, err := s.store.Repos(sess.UserKey)
	if err != nil {
		s.log.Error("list repositories", "error", err)
		writeError(w, http.StatusInternalServerError, "could not list the repositories")
		return
	}
	out := make([]store.PublicRepo, 0, len(repos))
	for _, repo := range repos {
		out = append(out, repo.Public())
	}
	// Repositories that need attention come first: monitored ones with a
	// verdict, then the ones still waiting for a policy.
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Monitored != out[j].Monitored {
			return out[i].Monitored
		}
		return out[i].FullName < out[j].FullName
	})
	writeJSON(w, http.StatusOK, map[string]any{"repos": out})
}

func (s *Server) handleRepo(w http.ResponseWriter, r *http.Request) {
	sess, _, ok := s.require(w, r)
	if !ok {
		return
	}
	repo, ok := s.repoOf(w, r, sess)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"repo": repo.Public()})
}

// handleSync refreshes the repository list in the background; progress reaches
// the dashboard over the event stream.
func (s *Server) handleSync(w http.ResponseWriter, r *http.Request) {
	_, user, ok := s.require(w, r)
	if !ok {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		if err := s.syncRepos(ctx, user); err != nil {
			s.log.Warn("repository sync", "user", user.Login, "error", err)
			s.events.Publish(user.Key, map[string]any{"type": "sync", "status": "failed", "error": err.Error()})
		}
	}()
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "syncing"})
}

// syncRepos lists the repositories of a user and records, for each of them,
// whether the default branch already carries a policy.
func (s *Server) syncRepos(ctx context.Context, user *store.User) error {
	provider, err := s.accounts.Provider(user.Provider)
	if err != nil {
		return err
	}
	token, err := s.accounts.Token(ctx, user)
	if err != nil {
		return err
	}
	s.events.Publish(user.Key, map[string]any{"type": "sync", "status": "started"})
	listed, err := provider.ListRepos(ctx, token, s.cfg.MaxRepos)
	if err != nil {
		return fmt.Errorf("list repositories: %w", err)
	}
	var wg sync.WaitGroup
	limit := make(chan struct{}, policyProbes)
	for _, item := range listed {
		wg.Add(1)
		limit <- struct{}{}
		go func(item forge.Repo) {
			defer wg.Done()
			defer func() { <-limit }()
			if repo, err := s.syncRepo(ctx, user, provider, token, item); err == nil {
				s.events.Publish(user.Key, map[string]any{"type": "repo", "repo": repo.Public()})
			} else {
				s.log.Warn("sync repository", "repo", item.FullName, "error", err)
			}
		}(item)
	}
	wg.Wait()
	s.events.Publish(user.Key, map[string]any{"type": "sync", "status": "finished", "count": len(listed)})
	return nil
}

func (s *Server) syncRepo(ctx context.Context, user *store.User, provider forge.Provider, token forge.Token, item forge.Repo) (*store.Repo, error) {
	key := store.Key(user.Provider, item.ID)
	repo, err := s.store.Repo(user.Key, key)
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			return nil, err
		}
		repo = &store.Repo{Key: key, Provider: user.Provider, ID: item.ID}
	}
	// Monitoring state, hook identity and history belong to the hub and are
	// preserved across syncs; everything else mirrors the forge.
	repo.FullName, repo.WebURL, repo.CloneURL = item.FullName, item.WebURL, item.CloneURL
	repo.DefaultBranch, repo.Private, repo.Admin = item.DefaultBranch, item.Private, item.Admin
	if repo.DefaultBranch != "" {
		_, found, err := provider.ReadFile(ctx, token, item, repo.DefaultBranch, forge.PolicyPath)
		if err != nil {
			// An empty repository or a permission gap must not drop the entry.
			s.log.Debug("policy probe", "repo", item.FullName, "error", err)
		} else {
			repo.HasPolicy, repo.PolicyAt = found, time.Now().UTC()
		}
	}
	if err := s.store.PutRepo(user.Key, repo); err != nil {
		return nil, err
	}
	return repo, nil
}

// handlePolicy commits a generated .swiftproof.json on the default branch.
func (s *Server) handlePolicy(w http.ResponseWriter, r *http.Request) {
	sess, user, ok := s.require(w, r)
	if !ok {
		return
	}
	repo, ok := s.repoOf(w, r, sess)
	if !ok {
		return
	}
	var body struct {
		Language string `json:"language"`
		Preview  bool   `json:"preview"`
	}
	if err := decodeBody(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	provider, token, ok := s.forgeAccess(w, r.Context(), user)
	if !ok {
		return
	}
	item := forgeRepo(repo)
	if repo.DefaultBranch == "" {
		writeError(w, http.StatusConflict, "this repository has no default branch yet")
		return
	}
	language := body.Language
	if language == "" {
		// Detecting from the default branch keeps the generated commands in
		// line with what the repository actually builds.
		entries, err := provider.ListRoot(r.Context(), token, item, repo.DefaultBranch)
		if err != nil {
			s.log.Warn("detect language", "repo", repo.FullName, "error", err)
		}
		language = forge.DetectLanguage(entries)
	}
	if !analysis.SupportedLanguage(language) {
		writeError(w, http.StatusBadRequest, "unsupported language")
		return
	}
	policy, err := s.runner.Policy(r.Context(), language)
	if err != nil {
		s.log.Error("generate policy", "error", err)
		writeError(w, http.StatusInternalServerError, "could not generate the policy")
		return
	}
	if body.Preview {
		writeJSON(w, http.StatusOK, map[string]any{"language": language, "policy": string(policy), "path": forge.PolicyPath})
		return
	}
	if repo.HasPolicy {
		writeError(w, http.StatusConflict, "this repository already has a policy on its default branch")
		return
	}
	message := "Add SwiftProof review policy\n\nGenerated by the SwiftProof hub for " + language + " and committed on " + repo.DefaultBranch + ".\nReview the sandbox image and the commands before relying on the report."
	if err := provider.CreateFile(r.Context(), token, item, repo.DefaultBranch, forge.PolicyPath, message, policy); err != nil {
		status := http.StatusBadGateway
		switch forge.StatusOf(err) {
		case http.StatusForbidden, http.StatusUnauthorized:
			status = http.StatusForbidden
		case http.StatusConflict, http.StatusUnprocessableEntity:
			status = http.StatusConflict
		}
		s.log.Warn("create policy", "repo", repo.FullName, "error", err)
		writeError(w, status, "the forge refused the commit: "+err.Error())
		return
	}
	updated, err := s.store.UpdateRepo(sess.UserKey, repo.Key, func(repo *store.Repo) error {
		repo.HasPolicy, repo.PolicyAt = true, time.Now().UTC()
		return nil
	})
	if err != nil {
		s.log.Error("update repository", "error", err)
		writeError(w, http.StatusInternalServerError, "the policy was committed but the state could not be saved")
		return
	}
	s.events.Publish(sess.UserKey, map[string]any{"type": "repo", "repo": updated.Public()})
	writeJSON(w, http.StatusCreated, map[string]any{"repo": updated.Public(), "language": language, "policy": string(policy)})
}

// handleMonitorOn installs the push webhook and analyzes the current tip.
func (s *Server) handleMonitorOn(w http.ResponseWriter, r *http.Request) {
	sess, user, ok := s.require(w, r)
	if !ok {
		return
	}
	repo, ok := s.repoOf(w, r, sess)
	if !ok {
		return
	}
	if !repo.HasPolicy {
		writeError(w, http.StatusConflict, "create the .swiftproof.json policy first")
		return
	}
	if !repo.Admin {
		writeError(w, http.StatusForbidden, "your account cannot manage webhooks on this repository")
		return
	}
	provider, token, ok := s.forgeAccess(w, r.Context(), user)
	if !ok {
		return
	}
	item := forgeRepo(repo)
	if repo.Monitored && repo.HookID != "" {
		// Replace a stale hook rather than accumulating duplicates.
		if err := provider.DeleteHook(r.Context(), token, item, repo.HookID); err != nil {
			s.log.Warn("delete stale hook", "repo", repo.FullName, "error", err)
		}
	}
	hookKey, err := secrets.Random(18)
	if err == nil && repo.HookKey != "" {
		hookKey = repo.HookKey
	}
	hookSecret, secretErr := secrets.Random(32)
	if err != nil || secretErr != nil {
		writeError(w, http.StatusInternalServerError, "could not prepare the webhook")
		return
	}
	hookID, err := provider.CreateHook(r.Context(), token, item, s.cfg.WebhookURL(hookKey), hookSecret)
	if err != nil {
		status := http.StatusBadGateway
		if code := forge.StatusOf(err); code == http.StatusForbidden || code == http.StatusUnauthorized {
			status = http.StatusForbidden
		}
		s.log.Warn("create hook", "repo", repo.FullName, "error", err)
		writeError(w, status, "the forge refused the webhook: "+err.Error())
		return
	}
	sealed, err := s.keys.Seal(hookSecret)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not store the webhook secret")
		return
	}
	updated, err := s.store.UpdateRepo(sess.UserKey, repo.Key, func(repo *store.Repo) error {
		repo.Monitored, repo.HookID, repo.HookKey, repo.HookSecret = true, hookID, hookKey, sealed
		return nil
	})
	if err != nil {
		s.log.Error("update repository", "error", err)
		writeError(w, http.StatusInternalServerError, "could not save the monitoring state")
		return
	}
	if err := s.store.PutHook(hookKey, store.HookRoute{UserKey: sess.UserKey, RepoKey: repo.Key, Provider: repo.Provider}); err != nil {
		s.log.Error("store hook route", "error", err)
	}
	s.events.Publish(sess.UserKey, map[string]any{"type": "repo", "repo": updated.Public()})
	// A first report right away makes the dashboard useful before the next push.
	if err := s.enqueueHead(r.Context(), user, updated, provider, token); err != nil {
		s.log.Warn("initial analysis", "repo", repo.FullName, "error", err)
	}
	writeJSON(w, http.StatusOK, map[string]any{"repo": updated.Public()})
}

// handleMonitorOff removes the webhook and stops analyzing pushes.
func (s *Server) handleMonitorOff(w http.ResponseWriter, r *http.Request) {
	sess, user, ok := s.require(w, r)
	if !ok {
		return
	}
	repo, ok := s.repoOf(w, r, sess)
	if !ok {
		return
	}
	provider, token, ok := s.forgeAccess(w, r.Context(), user)
	if !ok {
		return
	}
	if repo.HookID != "" {
		if err := provider.DeleteHook(r.Context(), token, forgeRepo(repo), repo.HookID); err != nil {
			s.log.Warn("delete hook", "repo", repo.FullName, "error", err)
		}
	}
	if repo.HookKey != "" {
		if err := s.store.DeleteHook(repo.HookKey); err != nil {
			s.log.Warn("delete hook route", "error", err)
		}
	}
	updated, err := s.store.UpdateRepo(sess.UserKey, repo.Key, func(repo *store.Repo) error {
		repo.Monitored, repo.HookID, repo.HookKey, repo.HookSecret = false, "", "", ""
		return nil
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not save the monitoring state")
		return
	}
	s.events.Publish(sess.UserKey, map[string]any{"type": "repo", "repo": updated.Public()})
	writeJSON(w, http.StatusOK, map[string]any{"repo": updated.Public()})
}

// handleAnalyze runs the analysis on demand, on a given commit or on the tip
// of the default branch.
func (s *Server) handleAnalyze(w http.ResponseWriter, r *http.Request) {
	sess, user, ok := s.require(w, r)
	if !ok {
		return
	}
	repo, ok := s.repoOf(w, r, sess)
	if !ok {
		return
	}
	var body struct {
		Commit string `json:"commit"`
		Ref    string `json:"ref"`
	}
	if err := decodeBody(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	provider, token, ok := s.forgeAccess(w, r.Context(), user)
	if !ok {
		return
	}
	if body.Commit != "" {
		job := analysis.Job{
			UserKey: sess.UserKey, RepoKey: repo.Key, Commit: body.Commit,
			Ref: body.Ref, Trigger: analysis.TriggerManual,
		}
		if err := s.runner.Enqueue(job); err != nil {
			writeError(w, http.StatusServiceUnavailable, err.Error())
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]string{"status": "queued", "commit": body.Commit})
		return
	}
	if err := s.enqueueHead(r.Context(), user, repo, provider, token); err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "queued"})
}

// enqueueHead schedules an analysis of the tip of the default branch.
func (s *Server) enqueueHead(ctx context.Context, user *store.User, repo *store.Repo, provider forge.Provider, token forge.Token) error {
	if repo.DefaultBranch == "" {
		return fmt.Errorf("this repository has no default branch yet")
	}
	head, err := provider.HeadCommit(ctx, token, forgeRepo(repo), repo.DefaultBranch)
	if err != nil {
		return fmt.Errorf("resolve %s: %w", repo.DefaultBranch, err)
	}
	return s.runner.Enqueue(analysis.Job{
		UserKey: user.Key, RepoKey: repo.Key, Commit: head.SHA,
		Ref: "refs/heads/" + repo.DefaultBranch, Message: head.Message, Author: head.Author,
		Trigger: analysis.TriggerManual,
	})
}

func (s *Server) handleRuns(w http.ResponseWriter, r *http.Request) {
	sess, _, ok := s.require(w, r)
	if !ok {
		return
	}
	repo, ok := s.repoOf(w, r, sess)
	if !ok {
		return
	}
	limit := store.MaxHistory
	if v, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && v > 0 && v < store.MaxHistory {
		limit = v
	}
	runs, err := s.store.History(sess.UserKey, repo.Key, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list the reports")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"repo": repo.Public(), "runs": runs})
}

// handleReport returns the rendered view: summary, ranked alerts and the
// modifications each alert points into.
func (s *Server) handleReport(w http.ResponseWriter, r *http.Request) {
	sess, _, ok := s.require(w, r)
	if !ok {
		return
	}
	repo, rec, ok := s.recordOf(w, r, sess)
	if !ok {
		return
	}
	parsed, err := report.Decode(rec.Raw)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "the stored report could not be read")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"repo": repo.Public(),
		"run":  rec.Run,
		"view": parsed.BuildView(),
	})
}

// handleReportRaw serves the stored confidence report itself, so a user keeps
// the artifact the CLI produced rather than the hub's rendering of it.
func (s *Server) handleReportRaw(w http.ResponseWriter, r *http.Request) {
	sess, _, ok := s.require(w, r)
	if !ok {
		return
	}
	_, rec, ok := s.recordOf(w, r, sess)
	if !ok {
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", "confidence-report-"+rec.Commit+".json"))
	w.WriteHeader(http.StatusOK)
	w.Write(rec.Raw)
}

func (s *Server) recordOf(w http.ResponseWriter, r *http.Request, sess secrets.Session) (*store.Repo, *store.Record, bool) {
	repo, ok := s.repoOf(w, r, sess)
	if !ok {
		return nil, nil, false
	}
	commit := r.PathValue("commit")
	if !store.ValidKey(commit) {
		writeError(w, http.StatusBadRequest, "invalid commit")
		return nil, nil, false
	}
	rec, err := s.store.Record(sess.UserKey, repo.Key, commit)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "no report for this commit")
			return nil, nil, false
		}
		writeError(w, http.StatusInternalServerError, "could not load the report")
		return nil, nil, false
	}
	if len(rec.Raw) == 0 {
		writeError(w, http.StatusNotFound, "this run produced no report")
		return nil, nil, false
	}
	return repo, rec, true
}

// handleEvents streams analysis updates of the signed-in user.
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	sess, _, ok := s.require(w, r)
	if !ok {
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "streaming is not supported")
		return
	}
	stream, cancel := s.events.Subscribe(sess.UserKey)
	defer cancel()

	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-store")
	h.Set("Connection", "keep-alive")
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "retry: 5000\n\n")
	flusher.Flush()

	heartbeat := time.NewTicker(25 * time.Second)
	defer heartbeat.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-heartbeat.C:
			// A comment frame keeps proxies from closing an idle stream.
			fmt.Fprint(w, ": keep-alive\n\n")
			flusher.Flush()
		case data, open := <-stream:
			if !open {
				return
			}
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		}
	}
}

// forgeAccess resolves the provider and a usable token, reporting the reason
// to the caller when the stored session can no longer be used.
func (s *Server) forgeAccess(w http.ResponseWriter, ctx context.Context, user *store.User) (forge.Provider, forge.Token, bool) {
	provider, err := s.accounts.Provider(user.Provider)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return nil, forge.Token{}, false
	}
	token, err := s.accounts.Token(ctx, user)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "sign in again: "+err.Error())
		return nil, forge.Token{}, false
	}
	return provider, token, true
}

func forgeRepo(repo *store.Repo) forge.Repo {
	return forge.Repo{
		ID: repo.ID, FullName: repo.FullName, WebURL: repo.WebURL, CloneURL: repo.CloneURL,
		DefaultBranch: repo.DefaultBranch, Private: repo.Private, Admin: repo.Admin,
	}
}
