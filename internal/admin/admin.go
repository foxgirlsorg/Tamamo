// Package admin serves Tamamo's admin API: the JSON endpoints that the
// optional web UI container (a separate project) talks to, plus the static
// files the checking-page preview loads. It serves no HTML pages itself.
package admin

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/tamamo/tamamo/internal/assets"
	"github.com/tamamo/tamamo/internal/config"
	"github.com/tamamo/tamamo/internal/stats"
	"github.com/tamamo/tamamo/web"
)

// Options configures the admin handler.
type Options struct {
	Config             *config.Manager
	Stats              *stats.Stats
	Assets             *assets.Store
	Version            string
	RunningListen      string
	RunningAdminListen string
}

const (
	maxJSONBody = 1 << 20
	csrfHeader  = "X-Tamamo-Request"
)

// ContentSecurityPolicy is sent with every admin API response. The responses
// are JSON, so nothing in them may load or run anything.
const ContentSecurityPolicy = "default-src 'none'; frame-ancestors 'none'"

// previewContentSecurityPolicy is sent with POST /api/preview, which returns
// a checking page as HTML. The page is shown in an iframe with srcdoc: its
// inline <style> needs 'unsafe-inline' for styles, its scripts load from
// /assets/challenge ('self') and its proof-of-work workers may be blob: URLs.
const previewContentSecurityPolicy = "default-src 'self'; img-src 'self' data: blob:; style-src 'self' 'unsafe-inline'; " +
	"script-src 'self'; worker-src 'self' blob:; connect-src 'self'; font-src 'self' data:; frame-src 'self'; " +
	"frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'"

type handler struct {
	o        Options
	mux      *http.ServeMux
	sessions *sessions
	limiter  *limiter
	setupMu  sync.Mutex
}

// New returns the admin API handler.
func New(o Options) http.Handler {
	h := &handler{o: o, mux: http.NewServeMux(), sessions: newSessions(), limiter: newLimiter()}
	m := h.mux

	m.HandleFunc("GET /{$}", h.root)
	m.HandleFunc("GET /api/state", h.state)
	m.HandleFunc("POST /api/setup", h.setup)
	m.HandleFunc("POST /api/login", h.login)
	m.HandleFunc("POST /api/logout", h.logout)

	m.HandleFunc("GET /api/config", h.auth(h.getConfig))
	m.HandleFunc("PUT /api/config", h.auth(h.putConfig))
	m.HandleFunc("GET /api/stats", h.auth(h.getStats))
	m.HandleFunc("POST /api/stats/reset", h.auth(h.resetStats))
	m.HandleFunc("POST /api/preview", h.auth(h.preview))
	m.HandleFunc("POST /api/upload/{slot}", h.auth(h.upload))
	m.HandleFunc("DELETE /api/upload/{slot}", h.auth(h.deleteUpload))
	m.HandleFunc("POST /api/password", h.auth(h.password))
	m.HandleFunc("POST /api/secret/rotate", h.auth(h.rotateSecret))
	m.HandleFunc("POST /api/test", h.auth(h.testRule))

	m.HandleFunc("GET /assets/img/{slot}", h.image)
	// The preview iframe loads the checking page's scripts and mascots.
	m.HandleFunc("GET /assets/challenge/", h.static)
	m.HandleFunc("GET /assets/mascot/", h.static)
	m.HandleFunc("/", h.notFound)
	return h
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// admin.domains (read per request: it can change at runtime): any other
	// Host gets an empty 404 that gives nothing away, setup included.
	if !config.AdminHostAllowed(h.o.Config.Get().Admin.Domains, r.Host) {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	hd := w.Header()
	hd.Set("Content-Security-Policy", ContentSecurityPolicy)
	hd.Set("X-Content-Type-Options", "nosniff")
	hd.Set("Referrer-Policy", "same-origin")
	hd.Set("X-Frame-Options", "DENY")
	hd.Set("Cross-Origin-Opener-Policy", "same-origin")

	isAPI := strings.HasPrefix(r.URL.Path, "/api/")
	if isAPI {
		hd.Set("Cache-Control", "no-store")
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
	default:
		// CSRF: browsers can't send custom headers cross-site without a CORS
		// preflight, which we never approve. Together with SameSite=Strict.
		if r.Header.Get(csrfHeader) != "1" {
			writeError(w, http.StatusForbidden, "missing "+csrfHeader+" header")
			return
		}
		if origin := r.Header.Get("Origin"); origin != "" && origin != "null" && !sameOrigin(origin, r) {
			writeError(w, http.StatusForbidden, "cross-origin request refused")
			return
		}
	}
	h.mux.ServeHTTP(w, r)
}

func sameOrigin(origin string, r *http.Request) bool {
	o := strings.TrimPrefix(strings.TrimPrefix(origin, "https://"), "http://")
	return strings.EqualFold(o, r.Host)
}

// ---- helpers ----------------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxJSONBody)
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(v); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			writeError(w, http.StatusRequestEntityTooLarge, "the request is too large")
		} else {
			writeError(w, http.StatusBadRequest, "the request body is not valid JSON: "+err.Error())
		}
		return false
	}
	return true
}

type ctxSession struct {
	token    string
	username string
}

type authedFunc func(w http.ResponseWriter, r *http.Request, s ctxSession)

func (h *handler) currentSession(r *http.Request) (ctxSession, bool) {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return ctxSession{}, false
	}
	s, ok := h.sessions.get(c.Value)
	if !ok {
		return ctxSession{}, false
	}
	return ctxSession{token: c.Value, username: s.username}, true
}

func (h *handler) auth(fn authedFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s, ok := h.currentSession(r)
		if !ok {
			writeError(w, http.StatusUnauthorized, "please sign in")
			return
		}
		fn(w, r, s)
	}
}

func (h *handler) sessionTTL() time.Duration {
	hrs := h.o.Config.Get().Admin.SessionHours
	if hrs < 1 {
		hrs = 24 * 7
	}
	return time.Duration(hrs) * time.Hour
}

// root answers GET / with a small JSON identity, so a client can tell this
// is the admin API.
func (h *handler) root(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"name":      "tamamo",
		"admin_api": true,
		"version":   h.o.Version,
	})
}

// notFound answers every other path with a JSON 404.
func (h *handler) notFound(w http.ResponseWriter, r *http.Request) {
	writeError(w, http.StatusNotFound, "not found")
}

// ---- static files -----------------------------------------------------------

func (h *handler) image(w http.ResponseWriter, r *http.Request) {
	slot := r.PathValue("slot")
	if !assets.ValidSlot(slot) || h.o.Assets == nil {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	h.o.Assets.Serve(w, r, slot)
}

func (h *handler) static(w http.ResponseWriter, r *http.Request) {
	rel := strings.TrimPrefix(r.URL.Path, "/assets/")
	clean := path.Clean("/" + rel)[1:]
	if clean == "" || clean != rel {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	for _, seg := range strings.Split(clean, "/") {
		if strings.HasPrefix(seg, ".") {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
	}
	switch {
	case strings.HasPrefix(clean, "challenge/") && !strings.HasSuffix(clean, ".html"):
		serveEmbedded(w, r, clean)
	case strings.HasPrefix(clean, "mascot/"):
		serveEmbedded(w, r, clean)
	default:
		writeError(w, http.StatusNotFound, "not found")
	}
}

func serveEmbedded(w http.ResponseWriter, r *http.Request, name string) {
	b, err := fs.ReadFile(web.FS, name)
	if err != nil {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	ct := mime.TypeByExtension(path.Ext(name))
	switch path.Ext(name) {
	case ".js", ".mjs":
		ct = "text/javascript; charset=utf-8"
	case ".css":
		ct = "text/css; charset=utf-8"
	case ".html":
		ct = "text/html; charset=utf-8"
	}
	if ct == "" {
		ct = "application/octet-stream"
	}
	w.Header().Set("Content-Type", ct)
	if strings.HasPrefix(name, "mascot/") {
		w.Header().Set("Cache-Control", "public, max-age=86400")
	} else {
		w.Header().Set("Cache-Control", "no-cache")
	}
	http.ServeContent(w, r, path.Base(name), time.Time{}, bytes.NewReader(b))
}
