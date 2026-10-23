// Package server is the HTTP handler for the protected sites: it serves
// Tamamo's own endpoints under /.tamamo/, applies the rules, hands out and
// checks proof-of-work challenges and proxies everything else upstream.
//
// It can also sit beside nginx instead of in front of the site: nginx asks
// GET /.tamamo/auth (auth_request) for every request, and on 401/403 sends the
// visitor to Tamamo with "X-Tamamo-Render: 1" to get the challenge or denied
// page. In that mode Tamamo never proxies.
package server

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/tamamo/tamamo/internal/assets"
	"github.com/tamamo/tamamo/internal/config"
	"github.com/tamamo/tamamo/internal/core"
	"github.com/tamamo/tamamo/internal/page"
	"github.com/tamamo/tamamo/internal/stats"
	"github.com/tamamo/tamamo/web"
)

// URLs of Tamamo's reserved endpoints.
const (
	Prefix    = "/.tamamo/"
	VerifyURL = "/.tamamo/api/verify"
	AuthURL   = "/.tamamo/auth"
	StaticURL = "/.tamamo/static"
	ImageURL  = "/.tamamo/static/img"
	HealthURL = "/.tamamo/health"

	// RenderHeader marks a request nginx forwards only to get a Tamamo page.
	RenderHeader = "X-Tamamo-Render"

	purposeChallenge = "challenge"
	purposePass      = "pass"
)

// Server implements http.Handler for the protected sites.
type Server struct {
	mgr    *config.Manager
	st     *stats.Stats
	as     *assets.Store
	static fs.FS

	derived atomic.Pointer[derived]
	proxies *proxyCache
	used    *usedSet
	fails   *failLimiter
	now     func() time.Time
}

// derived caches values computed from one config snapshot. It is rebuilt
// whenever the manager publishes a new *config.Config.
type derived struct {
	cfg     *config.Config
	trusted []netip.Prefix
	chal    *core.Signer
	pass    *core.Signer
}

// New creates the handler.
func New(mgr *config.Manager, st *stats.Stats, as *assets.Store) *Server {
	static, err := fs.Sub(web.FS, "challenge")
	if err != nil {
		panic(err) // the directory is embedded at build time
	}
	s := &Server{
		mgr:     mgr,
		st:      st,
		as:      as,
		static:  static,
		proxies: newProxyCache(),
		used:    newUsedSet(),
		fails:   newFailLimiter(),
		now:     time.Now,
	}
	s.proxies.server = s
	mgr.Subscribe(func(*config.Config) { s.proxies.reset() })
	return s
}

// state returns the current config and the values derived from it.
func (s *Server) state() *derived {
	cfg := s.mgr.Get()
	if d := s.derived.Load(); d != nil && d.cfg == cfg {
		return d
	}
	d := &derived{
		cfg:  cfg,
		chal: core.NewSigner(cfg.Secret, purposeChallenge),
		pass: core.NewSigner(cfg.Secret, purposePass),
	}
	for _, p := range cfg.Server.TrustedProxies {
		if pf, err := config.ParsePrefix(p); err == nil {
			d.trusted = append(d.trusted, pf)
		}
	}
	s.derived.Store(d)
	return d
}

func (s *Server) record(e stats.Event) {
	if s.st != nil {
		s.st.Record(e)
	}
}

// hostOnly lower-cases a Host header value and strips any port.
func hostOnly(h string) string {
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	h = strings.TrimSuffix(strings.Trim(h, "[]"), ".")
	return strings.ToLower(h)
}

// Outcomes of decide.
const (
	outAllow     = "allow"     // a rule or the default lets it through
	outPass      = "pass"      // a valid pass cookie lets it through
	outBlock     = "block"     // refused
	outChallenge = "challenge" // proof of work needed
)

// decision is what Tamamo wants to do with one request.
type decision struct {
	outcome    string
	site       *config.SiteView
	d          *derived
	ip         netip.Addr
	bind       string
	difficulty int
	method     string
	uri        string      // request URI (path + query) the decision is about
	ev         stats.Event // pre-filled; Kind is set when recorded
}

// decide applies the site's protection settings and rules to a request for
// method + uri (which differ from r's own for nginx subrequests).
func (s *Server) decide(r *http.Request, method, uri string) *decision {
	d := s.state()
	host := hostOnly(r.Host)
	site := s.mgr.ForHost(host)
	ip := core.ClientIP(r, d.cfg.Server.IPSource, d.trusted)
	path, _ := canonicalPath(uri)

	dc := &decision{
		site:   site,
		d:      d,
		ip:     ip,
		method: method,
		uri:    uri,
		ev: stats.Event{
			Time: s.now(),
			Site: site.ID,
			Host: host,
			Path: path,
			UA:   r.UserAgent(),
		},
	}
	if ip.IsValid() {
		dc.ev.IP = ip.String()
	}

	p := site.Protection
	if !p.Enabled {
		dc.outcome = outAllow
		return dc
	}
	action, difficulty := p.DefaultAction, p.Difficulty
	if rule := site.Rules.Match(config.RuleRequest{
		Method:    method,
		Host:      host,
		Path:      path,
		UserAgent: r.UserAgent(),
		IP:        ip,
		Header:    r.Header,
	}); rule != nil {
		action = rule.Action
		dc.ev.Rule = rule.Name
		if rule.Difficulty > 0 {
			difficulty = rule.Difficulty
		}
	}
	dc.difficulty = difficulty
	switch action {
	case config.ActionBlock:
		dc.outcome = outBlock
	case config.ActionAllow:
		dc.outcome = outAllow
	default:
		dc.bind = core.BindHash(ip, r.UserAgent(), p.BindIP, p.BindUserAgent)
		if s.validPass(dc, r) {
			dc.outcome = outPass
		} else {
			dc.outcome = outChallenge
		}
	}
	return dc
}

// validPass reports whether the request carries an unexpired pass cookie for
// this site, bound to this client, for at least the required difficulty.
func (s *Server) validPass(dc *decision, r *http.Request) bool {
	now := s.now().Unix()
	for _, c := range r.CookiesNamed(dc.site.Protection.CookieName) {
		var pc core.PassClaims
		if dc.d.pass.Verify(c.Value, &pc) != nil {
			continue
		}
		if pc.E > now && pc.S == dc.site.ID && pc.B == dc.bind && pc.D >= dc.difficulty {
			return true
		}
	}
	return false
}

func (dc *decision) record(s *Server, kind string) {
	dc.ev.Kind = kind
	s.record(dc.ev)
}

// isRenderOnly reports whether nginx sent this request just to get a page.
func isRenderOnly(r *http.Request) bool {
	return r.Header.Get(RenderHeader) == "1"
}

// originalRequest returns the method and URI of the request nginx is asking
// about, falling back to r's own.
func originalRequest(r *http.Request) (method, uri string) {
	method = r.Header.Get("X-Original-Method")
	if method == "" {
		method = r.Method
	}
	uri = r.Header.Get("X-Original-URI")
	if uri == "" {
		uri = r.Header.Get("X-Forwarded-Uri")
	}
	if uri == "" {
		uri = r.URL.RequestURI()
	}
	return method, uri
}

// ServeHTTP handles one request to a protected site.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, Prefix) {
		s.serveReserved(w, r)
		return
	}
	if isRenderOnly(r) {
		s.serveRenderOnly(w, r)
		return
	}

	dc := s.decide(r, r.Method, r.URL.RequestURI())
	switch dc.outcome {
	case outAllow, outPass:
		if dc.site.Target == "" {
			s.render(w, r, http.StatusBadGateway, page.Data{State: "error", MessageID: "upstream_missing"})
			return
		}
		dc.record(s, dc.outcome)
		s.proxy(w, r, dc.site.Target, dc.ip, dc.site.Protection.CookieName)
	case outBlock:
		dc.record(s, stats.KindBlock)
		s.render(w, r, http.StatusForbidden, page.Data{State: "denied"})
	default:
		dc.record(s, stats.KindChallenge)
		s.challenge(w, r, dc)
	}
}

// serveRenderOnly answers nginx's @tamamo location: it shows the challenge or
// denied page and never proxies. If the request would be let through after
// all (say the pass cookie was set meanwhile), the visitor is sent back to
// the page they asked for.
func (s *Server) serveRenderOnly(w http.ResponseWriter, r *http.Request) {
	method, uri := originalRequest(r)
	uri = safeRedirect(uri)
	dc := s.decide(r, method, uri)
	switch dc.outcome {
	case outAllow, outPass:
		w.Header().Set("Cache-Control", "no-store")
		http.Redirect(w, r, uri, http.StatusFound)
	case outBlock:
		dc.record(s, stats.KindBlock)
		s.render(w, r, http.StatusForbidden, page.Data{State: "denied"})
	default:
		dc.record(s, stats.KindChallenge)
		s.challenge(w, r, dc)
	}
}

// serveAuth answers nginx auth_request subrequests with an empty response:
// 204 to let the request through, 401 when a challenge is needed and 403
// when it is blocked. Challenges and blocks are counted when nginx asks for
// the page, so only allow/pass are recorded here.
func (s *Server) serveAuth(w http.ResponseWriter, r *http.Request) {
	method, uri := originalRequest(r)
	dc := s.decide(r, method, uri)
	w.Header().Set("Cache-Control", "no-store")
	switch dc.outcome {
	case outAllow, outPass:
		dc.record(s, dc.outcome)
		w.WriteHeader(http.StatusNoContent)
	case outBlock:
		w.WriteHeader(http.StatusForbidden)
	default:
		w.WriteHeader(http.StatusUnauthorized)
	}
}

// isNavigation reports whether the request looks like a browser loading a
// page (as opposed to fetch/XHR, images, scripts or websockets), i.e.
// whether showing an HTML challenge page makes sense.
func isNavigation(r *http.Request) bool {
	if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		return false
	}
	if r.Header.Get("X-Requested-With") != "" {
		return false
	}
	switch strings.ToLower(r.Header.Get("Sec-Fetch-Mode")) {
	case "navigate", "nested-navigate":
		return true
	case "cors", "no-cors", "same-origin", "websocket":
		return false
	}
	switch strings.ToLower(r.Header.Get("Sec-Fetch-Dest")) {
	case "", "document", "iframe", "frame", "empty":
		return true
	}
	return false
}

// challenge issues a fresh signed challenge and serves the checking page.
func (s *Server) challenge(w http.ResponseWriter, r *http.Request, dc *decision) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Add("Vary", "Cookie")
	if !isNavigation(r) {
		writeJSON(w, r, http.StatusForbidden, map[string]string{"error": "challenge_required"})
		return
	}
	claims := core.ChallengeClaims{
		R: core.NewRandom(),
		D: dc.difficulty,
		E: s.now().Add(time.Duration(dc.site.Protection.ChallengeMinutes) * time.Minute).Unix(),
		B: dc.bind,
		S: dc.site.ID,
	}
	redirect := "/"
	if dc.method == http.MethodGet || dc.method == http.MethodHead {
		redirect = safeRedirect(dc.uri)
	}
	s.render(w, r, http.StatusOK, page.Data{
		State:      "checking",
		Token:      dc.d.chal.Sign(claims),
		Random:     claims.R,
		Difficulty: dc.difficulty,
		Redirect:   redirect,
	})
}

// render serves a Tamamo page in the given state, styled with the page
// settings of the request's site. The page is rendered into a buffer first
// so a template error results in a clean 500.
func (s *Server) render(w http.ResponseWriter, r *http.Request, status int, d page.Data) {
	site := s.mgr.ForHost(r.Host)
	d.Host = hostOnly(r.Host)
	d.VerifyURL = VerifyURL
	d.StaticURL = StaticURL
	if s.as != nil {
		d.Images = s.as.URLs(ImageURL)
	}
	d.Lang = site.Page.PickLanguage(r.Header.Get("Accept-Language"))
	var buf bytes.Buffer
	if err := page.Render(&buf, site.Page, d); err != nil {
		slog.Error("rendering page failed", "state", d.State, "err", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Content-Length", strconv.Itoa(buf.Len()))
	h.Set("X-Robots-Tag", "noindex, nofollow")
	h.Set("Referrer-Policy", "same-origin")
	h.Set("X-Frame-Options", "SAMEORIGIN")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Add("Vary", "Accept-Language")
	if h.Get("Cache-Control") == "" {
		h.Set("Cache-Control", "no-store")
	}
	w.WriteHeader(status)
	if r.Method != http.MethodHead {
		_, _ = w.Write(buf.Bytes())
	}
}

func writeJSON(w http.ResponseWriter, r *http.Request, status int, v any) {
	b, _ := json.Marshal(v)
	h := w.Header()
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("Content-Length", strconv.Itoa(len(b)))
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	if r.Method != http.MethodHead {
		_, _ = w.Write(b)
	}
}
