package server

import (
	"bytes"
	"encoding/json"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/tamamo/tamamo/internal/config"
	"github.com/tamamo/tamamo/internal/core"
	"github.com/tamamo/tamamo/internal/page"
	"github.com/tamamo/tamamo/internal/stats"
)

// staticTypes overrides the system MIME table for the file types Tamamo
// ships, since some platforms map e.g. .js to text/plain.
var staticTypes = map[string]string{
	".js":    "text/javascript; charset=utf-8",
	".mjs":   "text/javascript; charset=utf-8",
	".css":   "text/css; charset=utf-8",
	".json":  "application/json",
	".wasm":  "application/wasm",
	".svg":   "image/svg+xml",
	".png":   "image/png",
	".jpg":   "image/jpeg",
	".jpeg":  "image/jpeg",
	".gif":   "image/gif",
	".webp":  "image/webp",
	".ico":   "image/x-icon",
	".woff":  "font/woff",
	".woff2": "font/woff2",
	".txt":   "text/plain; charset=utf-8",
	".map":   "application/json",
}

func (s *Server) serveReserved(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path
	switch {
	case p == HealthURL:
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			methodNotAllowed(w, "GET, HEAD")
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = io.WriteString(w, "ok")
	case p == AuthURL:
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			methodNotAllowed(w, "GET, HEAD")
			return
		}
		s.serveAuth(w, r)
	case p == VerifyURL:
		if r.Method != http.MethodPost {
			methodNotAllowed(w, "POST")
			return
		}
		s.verify(w, r)
	case strings.HasPrefix(p, ImageURL+"/"):
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			methodNotAllowed(w, "GET, HEAD")
			return
		}
		if s.as == nil {
			http.NotFound(w, r)
			return
		}
		s.as.Serve(w, r, strings.TrimPrefix(p, ImageURL+"/"))
	case strings.HasPrefix(p, StaticURL+"/"):
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			methodNotAllowed(w, "GET, HEAD")
			return
		}
		s.serveStatic(w, r, strings.TrimPrefix(p, StaticURL+"/"))
	default:
		http.NotFound(w, r)
	}
}

func methodNotAllowed(w http.ResponseWriter, allow string) {
	w.Header().Set("Allow", allow)
	http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
}

// serveStatic serves a file of the embedded challenge directory. Templates
// (*.html) and dotfiles are never served.
func (s *Server) serveStatic(w http.ResponseWriter, r *http.Request, name string) {
	if name == "" || !fs.ValidPath(name) || strings.HasSuffix(strings.ToLower(name), ".html") {
		http.NotFound(w, r)
		return
	}
	for _, seg := range strings.Split(name, "/") {
		if strings.HasPrefix(seg, ".") {
			http.NotFound(w, r)
			return
		}
	}
	fi, err := fs.Stat(s.static, name)
	if err != nil || !fi.Mode().IsRegular() {
		http.NotFound(w, r)
		return
	}
	data, err := fs.ReadFile(s.static, name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	ext := strings.ToLower(path.Ext(name))
	ct := staticTypes[ext]
	if ct == "" {
		ct = mime.TypeByExtension(ext)
	}
	if ct == "" {
		ct = "application/octet-stream"
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(data))
}

// verifyRequest is the body of POST /.tamamo/api/verify.
type verifyRequest struct {
	Token     string     `json:"token"`
	Nonce     flexString `json:"nonce"`
	ElapsedMs float64    `json:"elapsed_ms"`
	Redirect  string     `json:"redirect"`
}

// flexString accepts a JSON string or a JSON number (the solver may send the
// nonce either way).
type flexString string

func (f *flexString) UnmarshalJSON(b []byte) error {
	if len(b) > 0 && b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		*f = flexString(s)
		return nil
	}
	var n json.Number
	if err := json.Unmarshal(b, &n); err != nil {
		return err
	}
	*f = flexString(n.String())
	return nil
}

// safeRedirect returns target if it is a same-site absolute path, else "/".
// It rejects protocol-relative URLs ("//evil", "/\evil") and any control
// characters, which browsers strip before parsing (so "/\t/evil" would
// otherwise become "//evil").
func safeRedirect(target string) string {
	if target == "" || len(target) > 4096 || target[0] != '/' {
		return "/"
	}
	if strings.HasPrefix(target, "//") || strings.HasPrefix(target, "/\\") {
		return "/"
	}
	for i := 0; i < len(target); i++ {
		if c := target[i]; c < 0x20 || c == 0x7f || c == '\\' {
			return "/"
		}
	}
	return target
}

const maxSolveMs = 10 * 60 * 1000

// verify checks a solved challenge and issues the pass cookie.
func (s *Server) verify(w http.ResponseWriter, r *http.Request) {
	d := s.state()
	cfg := d.cfg
	site := s.mgr.ForHost(r.Host)
	p := site.Protection
	ip := core.ClientIP(r, cfg.Server.IPSource, d.trusted)
	now := s.now()

	ev := stats.Event{Time: now, Site: site.ID, Host: hostOnly(r.Host), UA: r.UserAgent()}
	if ip.IsValid() {
		ev.IP = ip.String()
	}

	if !s.fails.allowed(ip, p.MaxFailures, now) {
		w.Header().Set("Retry-After", "60")
		writeJSON(w, r, http.StatusTooManyRequests, map[string]any{
			"ok": false, "error": s.label(r, site, "too_many_attempts"),
		})
		return
	}

	// fail refuses the solution with the page label id, in the visitor's
	// language.
	fail := func(id string) {
		s.fails.fail(ip, now)
		ev.Kind = stats.KindFail
		s.record(ev)
		writeJSON(w, r, http.StatusForbidden, map[string]any{"ok": false, "error": s.label(r, site, id)})
	}

	var req verifyRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10))
	if err := dec.Decode(&req); err != nil {
		fail("bad_request")
		return
	}
	redirect := safeRedirect(req.Redirect)
	ev.Path = redirect
	if i := strings.IndexByte(ev.Path, '?'); i >= 0 {
		ev.Path = ev.Path[:i]
	}

	var c core.ChallengeClaims
	if err := d.chal.Verify(req.Token, &c); err != nil {
		fail("challenge_invalid")
		return
	}
	if c.S != site.ID {
		fail("challenge_wrong_site")
		return
	}
	if c.E <= now.Unix() {
		fail("challenge_expired")
		return
	}
	bind := core.BindHash(ip, r.UserAgent(), p.BindIP, p.BindUserAgent)
	if c.B != bind {
		fail("challenge_wrong_client")
		return
	}
	if c.D < 1 {
		fail("challenge_invalid")
		return
	}
	if _, ok := core.CheckPoW(c.R, string(req.Nonce), c.D); !ok {
		fail("proof_wrong")
		return
	}
	if !s.used.claim(c.R, c.E, now) {
		fail("challenge_used")
		return
	}

	pass := core.PassClaims{
		D: c.D,
		E: now.Add(time.Duration(p.PassHours) * time.Hour).Unix(),
		I: now.Unix(),
		B: bind,
		S: site.ID,
	}
	cookie := &http.Cookie{
		Name:     p.CookieName,
		Value:    d.pass.Sign(pass),
		Path:     "/",
		Domain:   p.CookieDomain,
		MaxAge:   p.PassHours * 3600,
		Expires:  time.Unix(pass.E, 0),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https"),
	}
	http.SetCookie(w, cookie)

	// Clamp before converting: out-of-range float->int conversions are
	// implementation-defined.
	ms := int64(0)
	if req.ElapsedMs > maxSolveMs {
		ms = maxSolveMs
	} else if req.ElapsedMs > 0 {
		ms = int64(req.ElapsedMs)
	}
	ev.Kind = stats.KindSolve
	ev.SolveMs = ms
	s.record(ev)
	writeJSON(w, r, http.StatusOK, map[string]any{"ok": true, "redirect": redirect})
}

// label returns the page label id (a config.Labels JSON name) of site in the
// language r asks for.
func (s *Server) label(r *http.Request, site *config.SiteView, id string) string {
	p := page.Translate(site.Page, site.Page.PickLanguage(r.Header.Get("Accept-Language")))
	if l := p.Labels.Get(id); l != "" {
		return l
	}
	return config.DefaultLabels().Get(id)
}
