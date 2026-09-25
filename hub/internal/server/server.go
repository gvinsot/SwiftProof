// Package server exposes the hub over HTTP: the OAuth sign-in, the repository
// dashboard API, the webhook receiver and the static web UI.
//
// Every state-changing endpoint is authenticated by a sealed session cookie
// and a double-submitted CSRF token; the webhook receiver authenticates the
// forge instead, with the per-repository secret. No endpoint ever returns a
// credential, and no repository data is served across accounts.
package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gvinsot/SwiftProof/hub/internal/accounts"
	"github.com/gvinsot/SwiftProof/hub/internal/analysis"
	"github.com/gvinsot/SwiftProof/hub/internal/config"
	"github.com/gvinsot/SwiftProof/hub/internal/events"
	"github.com/gvinsot/SwiftProof/hub/internal/secrets"
	"github.com/gvinsot/SwiftProof/hub/internal/store"
	hubweb "github.com/gvinsot/SwiftProof/hub/web"
)

const (
	sessionCookie = "swiftproof_hub_session"
	csrfHeader    = "X-SwiftProof-CSRF"
	// maxRequestBytes bounds any request body the hub parses.
	maxRequestBytes = 1 << 20
)

// Server wires the HTTP surface onto the store, the forges and the runner.
type Server struct {
	cfg      config.Config
	store    *store.Store
	accounts *accounts.Manager
	runner   *analysis.Runner
	events   *events.Broker
	keys     *secrets.Keyring
	log      *slog.Logger
	secure   bool
	version  string
	static   fs.FS
}

// New builds the server.
func New(cfg config.Config, s *store.Store, a *accounts.Manager, r *analysis.Runner, b *events.Broker, keys *secrets.Keyring, log *slog.Logger, version string) (*Server, error) {
	static, err := fs.Sub(hubweb.Assets, "public")
	if err != nil {
		return nil, err
	}
	return &Server{
		cfg: cfg, store: s, accounts: a, runner: r, events: b, keys: keys, log: log,
		secure: strings.HasPrefix(cfg.BaseURL, "https://"), version: version, static: static,
	}, nil
}

// Handler returns the routed, wrapped HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("GET /auth/{kind}/start", s.handleAuthStart)
	mux.HandleFunc("GET /auth/{kind}/callback", s.handleAuthCallback)
	mux.HandleFunc("POST /auth/logout", s.handleLogout)

	mux.HandleFunc("GET /api/me", s.handleMe)
	mux.HandleFunc("GET /api/repos", s.handleRepos)
	mux.HandleFunc("POST /api/repos/sync", s.handleSync)
	mux.HandleFunc("GET /api/repos/{repo}", s.handleRepo)
	mux.HandleFunc("POST /api/repos/{repo}/policy", s.handlePolicy)
	mux.HandleFunc("POST /api/repos/{repo}/monitor", s.handleMonitorOn)
	mux.HandleFunc("DELETE /api/repos/{repo}/monitor", s.handleMonitorOff)
	mux.HandleFunc("POST /api/repos/{repo}/analyze", s.handleAnalyze)
	mux.HandleFunc("GET /api/repos/{repo}/runs", s.handleRuns)
	mux.HandleFunc("GET /api/repos/{repo}/reports/{commit}", s.handleReport)
	mux.HandleFunc("GET /api/repos/{repo}/reports/{commit}/raw", s.handleReportRaw)
	mux.HandleFunc("GET /api/events", s.handleEvents)

	mux.HandleFunc("POST /hooks/{hook}", s.handleWebhook)
	mux.HandleFunc("GET /badge/{hook}", s.handleBadge)

	mux.HandleFunc("GET /", s.handleStatic)

	return s.recover(s.headers(s.logRequests(mux)))
}

// headers applies the same hardening the promotional site gets at the edge, so
// an on-premise deployment behind a plain reverse proxy is protected too. The
// UI ships no inline script, which lets the policy stay strict.
func (s *Server) headers(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; script-src 'self'; style-src 'self'; img-src 'self' data: https:; connect-src 'self'; font-src 'self'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
		if s.secure {
			h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		// Only the path is logged: query strings carry OAuth codes.
		s.log.Info("request", "method", r.Method, "path", r.URL.Path, "status", rec.status, "ms", time.Since(start).Milliseconds())
	})
}

func (s *Server) recover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				s.log.Error("panic", "path", r.URL.Path, "value", fmt.Sprint(v))
				http.Error(w, "internal error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// Flush forwards to the underlying writer so the event stream keeps working.
func (r *statusRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":      "ok",
		"version":     s.version,
		"cli":         s.runner.Version(r.Context()),
		"mode":        s.cfg.Mode,
		"queue":       s.runner.Pending(),
		"subscribers": s.events.Subscribers(),
	})
}

// handleStatic serves the embedded UI. Unknown paths fall back to the entry
// page so the hash-routed dashboard can be reloaded at any URL.
func (s *Server) handleStatic(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/")
	if name == "" {
		if _, err := s.session(r); err == nil {
			http.Redirect(w, r, "/app.html", http.StatusFound)
			return
		}
		name = "index.html"
	}
	f, err := s.static.Open(name)
	if err != nil {
		name = "index.html"
		if f, err = s.static.Open(name); err != nil {
			http.NotFound(w, r)
			return
		}
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || info.IsDir() {
		http.NotFound(w, r)
		return
	}
	// The assets ship inside the image and change with it; a short revalidated
	// lifetime keeps an upgraded container from serving a stale dashboard.
	w.Header().Set("Cache-Control", "public, max-age=300")
	http.ServeContent(w, r, name, info.ModTime(), f.(io.ReadSeeker))
}

// session authenticates the cookie of a request.
func (s *Server) session(r *http.Request) (secrets.Session, error) {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return secrets.Session{}, secrets.ErrInvalid
	}
	return s.keys.ReadSession(c.Value, time.Now())
}

// require authenticates a request and, for state-changing methods, checks the
// CSRF token and the origin. It writes the error response itself.
func (s *Server) require(w http.ResponseWriter, r *http.Request) (secrets.Session, *store.User, bool) {
	sess, err := s.session(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "sign in to continue")
		return secrets.Session{}, nil, false
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		if !s.keys.CheckCSRF(sess, r.Header.Get(csrfHeader)) {
			writeError(w, http.StatusForbidden, "invalid CSRF token")
			return secrets.Session{}, nil, false
		}
		if !s.sameOrigin(r) {
			writeError(w, http.StatusForbidden, "cross-origin request refused")
			return secrets.Session{}, nil, false
		}
	}
	user, err := s.store.User(sess.UserKey)
	if err != nil {
		s.clearSession(w)
		writeError(w, http.StatusUnauthorized, "sign in again")
		return secrets.Session{}, nil, false
	}
	return sess, user, true
}

// sameOrigin rejects a state-changing request whose Origin is not the
// deployment itself. Browsers always send it for those methods.
func (s *Server) sameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		// Not a browser form or fetch; the CSRF token already authenticated it.
		return true
	}
	got, err := url.Parse(origin)
	if err != nil {
		return false
	}
	want, err := url.Parse(s.cfg.BaseURL)
	if err != nil {
		return false
	}
	if strings.EqualFold(got.Host, want.Host) {
		return true
	}
	// Behind a proxy the public host is what the browser used.
	return strings.EqualFold(got.Host, r.Host)
}

func (s *Server) setSession(w http.ResponseWriter, sess secrets.Session) error {
	value, err := s.keys.SignSession(sess)
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.secure,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Unix(sess.Expires, 0),
	})
	return nil
}

func (s *Server) clearSession(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: "", Path: "/", HttpOnly: true,
		Secure: s.secure, SameSite: http.SameSiteLaxMode, MaxAge: -1,
	})
}

// repoOf resolves the repository named in the path, scoped to the session.
func (s *Server) repoOf(w http.ResponseWriter, r *http.Request, sess secrets.Session) (*store.Repo, bool) {
	key := r.PathValue("repo")
	if !store.ValidKey(key) {
		writeError(w, http.StatusBadRequest, "invalid repository")
		return nil, false
	}
	repo, err := s.store.Repo(sess.UserKey, key)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "unknown repository")
			return nil, false
		}
		s.log.Error("load repository", "error", err)
		writeError(w, http.StatusInternalServerError, "could not load the repository")
		return nil, false
	}
	return repo, true
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		return
	}
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

// decodeBody parses a bounded JSON request body.
func decodeBody(r *http.Request, out any) error {
	defer r.Body.Close()
	d := json.NewDecoder(io.LimitReader(r.Body, maxRequestBytes))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("invalid request body")
	}
	return nil
}
