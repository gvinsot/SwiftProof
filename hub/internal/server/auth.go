package server

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gvinsot/SwiftProof/hub/internal/secrets"
	"github.com/gvinsot/SwiftProof/hub/internal/store"
)

const stateCookie = "swiftproof_hub_state"

// handleAuthStart begins an OAuth flow on the requested forge.
func (s *Server) handleAuthStart(w http.ResponseWriter, r *http.Request) {
	kind := r.PathValue("kind")
	provider, err := s.accounts.Provider(kind)
	if err != nil {
		writeError(w, http.StatusNotFound, "this forge is not configured on this deployment")
		return
	}
	next := safeNext(r.URL.Query().Get("next"))
	state, err := s.keys.SignState(kind, next, time.Now())
	if err != nil {
		s.log.Error("sign state", "error", err)
		writeError(w, http.StatusInternalServerError, "could not start the sign-in")
		return
	}
	// The state is authenticated on its own; pinning it to a cookie also ties
	// the callback to the browser that started the flow.
	http.SetCookie(w, &http.Cookie{
		Name: stateCookie, Value: state, Path: "/auth/", HttpOnly: true,
		Secure: s.secure, SameSite: http.SameSiteLaxMode, MaxAge: 600,
	})
	http.Redirect(w, r, provider.AuthURL(state, s.cfg.CallbackURL(kind)), http.StatusFound)
}

// handleAuthCallback completes the flow, stores the sealed token and opens a
// session.
func (s *Server) handleAuthCallback(w http.ResponseWriter, r *http.Request) {
	kind := r.PathValue("kind")
	provider, err := s.accounts.Provider(kind)
	if err != nil {
		writeError(w, http.StatusNotFound, "this forge is not configured on this deployment")
		return
	}
	query := r.URL.Query()
	if e := query.Get("error"); e != "" {
		s.failAuth(w, r, "the forge refused the authorization")
		return
	}
	code, state := query.Get("code"), query.Get("state")
	cookie, err := r.Cookie(stateCookie)
	if err != nil || code == "" || state == "" || cookie.Value != state {
		s.failAuth(w, r, "the sign-in could not be verified, start again")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: stateCookie, Value: "", Path: "/auth/", MaxAge: -1, HttpOnly: true, Secure: s.secure})
	stateKind, next, err := s.keys.ReadState(state, time.Now())
	if err != nil || stateKind != kind {
		s.failAuth(w, r, "the sign-in expired, start again")
		return
	}

	token, err := provider.Exchange(r.Context(), code, s.cfg.CallbackURL(kind))
	if err != nil {
		s.log.Warn("token exchange", "forge", kind, "error", err)
		s.failAuth(w, r, "the forge did not issue a token")
		return
	}
	account, err := provider.CurrentUser(r.Context(), token)
	if err != nil {
		s.log.Warn("current user", "forge", kind, "error", err)
		s.failAuth(w, r, "the forge did not return the account")
		return
	}

	key := store.Key(kind, account.ID)
	user, err := s.store.User(key)
	if err != nil {
		user = &store.User{Key: key, Provider: kind, ID: account.ID}
	}
	user.Login, user.Name, user.AvatarURL, user.WebURL = account.Login, account.Name, account.AvatarURL, account.WebURL
	if err := s.accounts.Save(user, token); err != nil {
		s.log.Error("save account", "error", err)
		s.failAuth(w, r, "the account could not be stored")
		return
	}

	sess, err := secrets.NewSession(user.Key, kind, user.Login, s.cfg.SessionTTL, time.Now())
	if err == nil {
		err = s.setSession(w, sess)
	}
	if err != nil {
		s.log.Error("open session", "error", err)
		s.failAuth(w, r, "the session could not be opened")
		return
	}

	// The first listing is the slow part of a sign-in: run it in the
	// background and let the dashboard stream in what it finds.
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		if err := s.syncRepos(ctx, user); err != nil {
			s.log.Warn("initial repository sync", "user", user.Login, "error", err)
		}
	}()

	if next == "" {
		next = "/app.html"
	}
	http.Redirect(w, r, next, http.StatusFound)
}

// failAuth returns the user to the sign-in page with a readable reason.
func (s *Server) failAuth(w http.ResponseWriter, r *http.Request, reason string) {
	s.clearSession(w)
	http.Redirect(w, r, "/index.html?error="+url.QueryEscape(reason), http.StatusFound)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if _, _, ok := s.require(w, r); !ok {
		return
	}
	s.clearSession(w)
	writeJSON(w, http.StatusOK, map[string]string{"status": "signed out"})
}

// handleMe describes the session and the deployment to the UI.
func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	forges := make([]string, 0, len(s.accounts.Providers()))
	for kind := range s.accounts.Providers() {
		forges = append(forges, kind)
	}
	sess, err := s.session(r)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"authenticated": false,
			"forges":        forges,
			"version":       s.version,
		})
		return
	}
	user, err := s.store.User(sess.UserKey)
	if err != nil {
		s.clearSession(w)
		writeJSON(w, http.StatusOK, map[string]any{"authenticated": false, "forges": forges, "version": s.version})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"authenticated": true,
		"forges":        forges,
		"version":       s.version,
		"mode":          s.cfg.Mode,
		"csrf":          s.keys.CSRF(sess),
		"expires":       sess.Expires,
		"user": map[string]string{
			"login": user.Login, "name": user.Name, "provider": user.Provider,
			"avatar_url": user.AvatarURL, "web_url": user.WebURL,
		},
	})
}

// safeNext keeps a post-login redirect inside the deployment.
func safeNext(next string) string {
	if next == "" || !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") {
		return ""
	}
	if strings.Contains(next, "\n") || strings.Contains(next, "\r") {
		return ""
	}
	return next
}
