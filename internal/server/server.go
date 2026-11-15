// Package server is the HTTP handler for the protected sites: it serves
// Tamamo's own endpoints under /.tamamo/, applies the rules, hands out and
// checks proof-of-work challenges and proxies everything else upstream.
//
// It can also sit beside nginx instead of in front of the site: nginx asks
// GET /.tamamo/auth (auth_request) for every request, and on 401/403 sends the
// visitor to Tamamo with "X-Tamamo-Render: 1" to get the challenge or denied
// page. In that mode Tamamo never proxies. Caddy (forward_auth) and Traefik
// (ForwardAuth) ask GET /.tamamo/forward-auth instead, which answers with the
// page itself.
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
	"sync"
	"sync/atomic"
	"time"

	"github.com/foxgirlsorg/tamamo/internal/assets"
	"github.com/foxgirlsorg/tamamo/internal/checks"
	"github.com/foxgirlsorg/tamamo/internal/config"
	"github.com/foxgirlsorg/tamamo/internal/core"
	"github.com/foxgirlsorg/tamamo/internal/modules"
	"github.com/foxgirlsorg/tamamo/internal/page"
	"github.com/foxgirlsorg/tamamo/internal/stats"
	"github.com/foxgirlsorg/tamamo/module"
	"github.com/foxgirlsorg/tamamo/web"
)

// URLs of Tamamo's reserved endpoints.
const (
	Prefix    = "/.tamamo/"
	VerifyURL = "/.tamamo/api/verify"
	AuthURL   = "/.tamamo/auth"
	// ForwardAuthURL is for proxies whose auth check returns the auth
	// server's own answer to the visitor (Caddy forward_auth, Traefik
	// ForwardAuth): 204 lets the request through, anything else carries the
	// checking or denied page.
	ForwardAuthURL = "/.tamamo/forward-auth"
	StaticURL      = "/.tamamo/static"
	ImageURL       = "/.tamamo/static/img"
	HealthURL      = "/.tamamo/health"
	// PassURL hands the page's script a short-lived copy of the visitor's
	// pass, for sites that accept this site's passes (another domain).
	PassURL = "/.tamamo/api/pass"
	// PassHeader carries that copy to the other site.
	PassHeader = "X-Tamamo-Pass"

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
	bans    *banList // clients banned by the honeypot
	now     func() time.Time

	bots       *checks.BotVerifier
	host       *modules.Host // runs the Go modules
	checkMu    sync.Mutex
	checkCache map[string]any // built-in checks by scope and settings
}

// derived caches values computed from one config snapshot. It is rebuilt
// whenever the manager publishes a new *config.Config.
type derived struct {
	cfg     *config.Config
	trusted []netip.Prefix
	chal    *core.Signer
	pass    *core.Signer
	mods    []*modules.Instance                // running modules, in config order
	core    map[*config.Protection]*siteChecks // built-in checks per protection section
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
		bans:    newBanList(),
		now:     time.Now,
		bots:    checks.NewBotVerifier(nil),
	}
	dataDir := ""
	if as != nil {
		dataDir = as.DataDir()
	}
	s.host = modules.NewHost(dataDir)
	s.proxies.server = s
	mgr.Subscribe(func(*config.Config) {
		s.proxies.reset()
		s.state() // start and stop modules right away, not on the next request
	})
	s.state()
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
		mods: s.host.Apply(cfg),
		core: s.buildChecks(cfg),
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
	s.observe(e)
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
	uri        string          // request URI (path + query) the decision is about
	req        *module.Request // what modules see of the request
	ev         stats.Event     // pre-filled; Kind is set when recorded
}

// decide applies the site's protection settings and rules to a request for
// method + uri (which differ from r's own for nginx subrequests).
func (s *Server) decide(r *http.Request, method, uri string) *decision {
	d := s.state()
	host := hostOnly(r.Host)
	site := s.mgr.ForHost(host)
	ip := core.ClientIP(r, d.cfg.Server.IPSource, d.trusted)
	path, query := canonicalPath(uri)

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

	dc.req = &module.Request{
		Site:      site.ID,
		Method:    method,
		Host:      host,
		Path:      path,
		Query:     query,
		UserAgent: r.UserAgent(),
		IP:        ip,
		Header:    r.Header,
	}

	p := site.Protection
	if !p.Enabled {
		dc.outcome = outAllow
		return dc
	}
	// The honeypot comes before everything else, unprotected paths included:
	// a banned client gets nothing from a site whose honeypot is on.
	if p.Honeypot.Enabled && s.honeypot(dc, path, uri) {
		dc.outcome = outBlock
		return dc
	}
	// Unprotected paths skip everything. A path that can be read two ways
	// must be unprotected in both readings.
	if site.HasUnprotected() && site.Unprotected(path) && site.Unprotected(literalPath(uri)) {
		dc.outcome = outAllow
		dc.ev.Rule = "unprotected path"
		return dc
	}
	// A browser asks before it sends a script's request with the pass
	// header to another domain. That question can't carry the pass.
	if method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" && s.trustedOrigin(site, r) {
		dc.outcome = outAllow
		dc.ev.Rule = "cors preflight"
		return dc
	}
	action, difficulty := p.DefaultAction, p.Difficulty
	// Bypass headers, the rate limit, webhooks and modules run first; the
	// first one with an opinion decides.
	md, label, decided := s.runChecks(r, d, site, dc.req)
	if decided {
		action = md.Action
		dc.ev.Rule = label
		if md.Difficulty > 0 {
			difficulty = md.Difficulty
		}
	} else {
		rr := config.RuleRequest{
			Method:    method,
			Host:      host,
			Path:      path,
			UserAgent: r.UserAgent(),
			IP:        ip,
			Header:    r.Header,
		}
		rule := site.Rules.Match(rr)
		ruleAction := func(rule *config.Rule) string {
			if rule == nil {
				return p.DefaultAction
			}
			return rule.Action
		}
		// A path with encoded slashes or dot segments can be read two ways,
		// and the upstream may not read it the way the rules did. Match the
		// other reading too and keep the stricter outcome, so such a path
		// can't borrow an allow rule meant for a different page.
		if lit := literalPath(uri); lit != path {
			rr.Path = lit
			if other := site.Rules.Match(rr); actionRank(ruleAction(other)) > actionRank(ruleAction(rule)) {
				rule = other
			}
		}
		if rule != nil {
			action = rule.Action
			dc.ev.Rule = rule.Name
			if rule.Difficulty > 0 {
				difficulty = rule.Difficulty
			}
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

// honeypot reports whether the request must be refused by the site's
// honeypot: the client is banned, or this request opens a trap path and bans
// it. Clients whose address is unknown or is one of server.trusted_proxies
// are never banned: that would ban every visitor behind the proxy.
func (s *Server) honeypot(dc *decision, path, uri string) bool {
	ip := dc.ip
	if !ip.IsValid() {
		return false
	}
	for _, pf := range dc.d.trusted {
		if pf.Contains(ip.Unmap()) {
			return false
		}
	}
	now := s.now()
	if s.bans.banned(ip, now) {
		dc.ev.Rule = "honeypot ban"
		return true
	}
	if !dc.site.Trap(path) && !dc.site.Trap(literalPath(uri)) {
		return false
	}
	hours := dc.site.Protection.Honeypot.BanHours
	if hours <= 0 {
		hours = dc.site.Protection.PassHours
	}
	s.bans.ban(ip, now.Add(time.Duration(hours)*time.Hour), now)
	dc.ev.Rule = "honeypot"
	return true
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
		if !pc.X && pc.E > now && pc.S == dc.site.ID && pc.B == dc.bind && pc.D >= dc.difficulty {
			return true
		}
	}
	if len(dc.site.Trusts) == 0 {
		return false
	}
	// A pass earned on a site this one trusts, sent by the page's script.
	for _, v := range r.Header.Values(PassHeader) {
		var pc core.PassClaims
		if dc.d.pass.Verify(strings.TrimSpace(v), &pc) != nil || !pc.X || pc.E <= now || pc.D < dc.difficulty {
			continue
		}
		from := dc.site.Trusts[pc.S]
		if from == nil {
			continue
		}
		fp := from.Protection
		if pc.B == core.BindHash(dc.ip, r.UserAgent(), fp.BindIP, fp.BindUserAgent) {
			return true
		}
	}
	return false
}

// trustedOrigin reports whether the request's Origin is a site whose passes
// site accepts.
func (s *Server) trustedOrigin(site *config.SiteView, r *http.Request) bool {
	if len(site.Trusts) == 0 {
		return false
	}
	origin := r.Header.Get("Origin")
	_, rest, ok := strings.Cut(origin, "://")
	if !ok || rest == "" || strings.ContainsAny(rest, "/ ") {
		return false
	}
	return site.Trusts[s.mgr.ForHost(rest).ID] != nil
}

// authEndpoints reports whether /.tamamo/auth, /.tamamo/forward-auth and the
// render-only header are in use (server.auth_endpoints).
func authEndpoints(cfg *config.Config) bool {
	switch cfg.Server.AuthEndpoints {
	case "on":
		return true
	case "off":
		return false
	}
	return cfg.Server.Target == ""
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
	if isRenderOnly(r) && authEndpoints(s.mgr.Get()) {
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
		s.proxy(w, r, dc)
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

// serveForwardAuth answers the auth check of Caddy (forward_auth) and Traefik
// (ForwardAuth). Both hand a non-2xx answer to the visitor as it is, so the
// checking page (401) and the denied page (403) are served right here.
//
// Traefik calls the endpoint with its own Host header and puts the visitor's
// in X-Forwarded-Host, which is used when the proxy is trusted.
func (s *Server) serveForwardAuth(w http.ResponseWriter, r *http.Request) {
	d := s.state()
	if h := r.Header.Get("X-Forwarded-Host"); h != "" && core.PeerTrusted(r, d.cfg.Server.IPSource, d.trusted) {
		r.Host = h
	}
	// Only the headers the proxy sets itself. X-Original-URI comes straight
	// from the visitor here, who could name a page that is let through.
	method, uri := r.Header.Get("X-Forwarded-Method"), r.Header.Get("X-Forwarded-Uri")
	if method == "" {
		method = r.Method
	}
	if uri == "" {
		uri = r.URL.RequestURI()
	}
	dc := s.decide(r, method, uri)
	w.Header().Set("Cache-Control", "no-store")
	switch dc.outcome {
	case outAllow, outPass:
		dc.record(s, dc.outcome)
		w.WriteHeader(http.StatusNoContent)
	case outBlock:
		dc.record(s, stats.KindBlock)
		s.render(w, r, http.StatusForbidden, page.Data{State: "denied"})
	default:
		dc.record(s, stats.KindChallenge)
		s.challengeStatus(w, r, dc, http.StatusUnauthorized)
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
	s.challengeStatus(w, r, dc, http.StatusOK)
}

// challengeStatus is challenge with the status code of the page.
func (s *Server) challengeStatus(w http.ResponseWriter, r *http.Request, dc *decision, status int) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Add("Vary", "Cookie")
	// Browsers leave Sec-Fetch-* out on plain http, so two more signs of a
	// script request: a GET never carries Origin when it loads a page, and a
	// request from a site whose passes are accepted here is that site's
	// script talking to its API.
	trusted := s.trustedOrigin(dc.site, r)
	scripted := trusted || (r.Header.Get("Origin") != "" && (dc.method == http.MethodGet || dc.method == http.MethodHead))
	if scripted || !isNavigation(r) {
		// Let the script of a trusted site read this answer, so it can
		// fetch a fresh pass and try again.
		if trusted {
			w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Add("Vary", "Origin")
		}
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
	s.render(w, r, status, page.Data{
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
		d.MascotCredit = page.DefaultMascots(s.as.Custom())
	}
	d.Lang = site.Page.PickLanguage(r.Header.Get("Accept-Language"))
	d.Modules = s.pageModules(site.ID, d.Host, d.State, d.Lang)
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
