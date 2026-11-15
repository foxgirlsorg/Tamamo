package server

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/foxgirlsorg/tamamo/internal/checks"
	"github.com/foxgirlsorg/tamamo/internal/config"
)

// ---- auth endpoints -----------------------------------------------------------

func TestAuthEndpointsFollowSetting(t *testing.T) {
	for _, tc := range []struct {
		mode   string
		target bool
		open   bool
	}{
		{"auto", true, false}, {"auto", false, true}, {"on", true, true}, {"off", false, false}, {"", true, false},
	} {
		e := fxNew(t, func(c *config.Config) {
			c.Protection.DefaultAction = config.ActionAllow
			c.Server.AuthEndpoints = tc.mode
			if !tc.target {
				c.Server.Target = ""
			}
		})
		for _, u := range []string{AuthURL, ForwardAuthURL} {
			r := fxReq(http.MethodGet, u)
			r.Header.Set("X-Original-URI", "/x")
			r.Header.Set("X-Forwarded-Uri", "/x")
			got := e.do(r).Code
			if open := got == http.StatusNoContent; open != tc.open || (!open && got != http.StatusNotFound) {
				t.Errorf("auth_endpoints=%q target=%v %s: %d", tc.mode, tc.target, u, got)
			}
		}
	}
	// With the endpoints closed, a visitor's render-only header is ignored
	// and the request is handled like any other.
	e := fxNew(t, func(c *config.Config) {
		c.Protection.DefaultAction = config.ActionAllow
		c.Server.AuthEndpoints = "auto"
	})
	r := fxReq(http.MethodGet, "/page")
	r.Header.Set(RenderHeader, "1")
	if w := e.do(r); !e.proxied(w) {
		t.Errorf("render-only header changed a proxied request: %d", w.Code)
	}
}

// ---- unprotected paths --------------------------------------------------------

func TestUnprotectedPaths(t *testing.T) {
	e := fxNew(t, func(c *config.Config) {
		c.Protection.DefaultAction = config.ActionBlock
		c.Protection.UnprotectedPaths = []string{"/robots.txt", "/.well-known/*", "re:^/static/.+\\.css$"}
		// Even checks that run before the rules don't see them.
		c.Protection.RateLimit = config.RateLimit{Enabled: true, Requests: 1, WindowSeconds: 60, Action: config.ActionBlock}
		c.Rules = []config.Rule{fxRule("everything", config.ActionBlock, config.Match{Paths: []string{"*"}})}
	})
	for i := 0; i < 3; i++ {
		for _, p := range []string{"/robots.txt", "/.well-known/security.txt", "/static/a/site.css"} {
			if w := e.get(p); !e.proxied(w) {
				t.Fatalf("%s (round %d): %d, want it let through", p, i, w.Code)
			}
		}
	}
	for _, p := range []string{"/robots.txt.bak", "/static/site.js", "/", "/search/..%2Frobots.txt", "/search/../robots.txt", "/x/..%2F.well-known/y"} {
		if w := e.do(fxRaw(p)); e.proxied(w) {
			t.Errorf("%s: let through", p)
		}
	}
	// A bad pattern is refused when saving.
	err := e.s.mgr.Update(func(c *config.Config) error {
		c.Protection.UnprotectedPaths = []string{"re:("}
		return nil
	})
	if err == nil {
		t.Error("a broken unprotected path pattern was accepted")
	}
}

// ---- verified bots ------------------------------------------------------------

type fakeDNS struct {
	ptr   map[string][]string // ip -> names
	hosts map[string][]string // name -> ips
	fail  bool
	calls int
}

func (f *fakeDNS) LookupAddr(_ context.Context, addr string) ([]string, error) {
	f.calls++
	if f.fail {
		return nil, errors.New("dns timeout")
	}
	if n, ok := f.ptr[addr]; ok {
		return n, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: addr, IsNotFound: true}
}

func (f *fakeDNS) LookupHost(_ context.Context, host string) ([]string, error) {
	if a, ok := f.hosts[host]; ok {
		return a, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

const googleUA = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"

func TestVerifiedBots(t *testing.T) {
	dns := &fakeDNS{
		ptr: map[string][]string{
			"66.249.66.1":  {"crawl-66-249-66-1.googlebot.com."},
			"203.0.113.5":  {"crawl.googlebot.com.evil.example."}, // wrong domain
			"203.0.113.6":  {"fake.googlebot.com."},               // doesn't resolve back
			"203.0.113.77": {"host.example.net."},
		},
		hosts: map[string][]string{
			"crawl-66-249-66-1.googlebot.com": {"66.249.66.1"},
			"fake.googlebot.com":              {"198.51.100.1"},
		},
	}
	newEnv := func(enabled bool, action string) *fxEnv {
		e := fxNew(t, func(c *config.Config) {
			c.Protection.DefaultAction = config.ActionChallenge
			c.Protection.VerifiedBots = config.VerifiedBots{Enabled: enabled, Action: action}
			c.Rules = []config.Rule{fxRule("search engines", config.ActionAllow, config.Match{UserAgents: []string{"*Googlebot*"}})}
		})
		e.s.bots = checks.NewBotVerifier(dns)
		return e
	}
	from := func(e *fxEnv, ip, ua string) *httptest.ResponseRecorder {
		r := fxReq(http.MethodGet, "/page")
		r.RemoteAddr = ip + ":4000"
		r.Header.Set("User-Agent", ua)
		return e.do(r)
	}

	e := newEnv(true, config.ActionBlock)
	if w := from(e, "66.249.66.1", googleUA); !e.proxied(w) {
		t.Errorf("real Googlebot: %d", w.Code)
	}
	for _, ip := range []string{"203.0.113.5", "203.0.113.6", "203.0.113.77", "203.0.113.200"} {
		if w := from(e, ip, googleUA); w.Code != http.StatusForbidden || e.proxied(w) {
			t.Errorf("fake Googlebot from %s: %d", ip, w.Code)
		}
	}
	// Other visitors are not looked up at all.
	before := dns.calls
	if w := from(e, "203.0.113.200", fxUA); w.Code != http.StatusOK || e.proxied(w) {
		t.Errorf("ordinary visitor: %d", w.Code)
	}
	if dns.calls != before {
		t.Error("an ordinary visitor caused a DNS lookup")
	}
	// Answers are remembered.
	from(e, "66.249.66.1", googleUA)
	from(e, "203.0.113.5", googleUA)
	if dns.calls != before {
		t.Errorf("verdicts were not cached: %d more lookups", dns.calls-before)
	}

	// challenge instead of block.
	e = newEnv(true, config.ActionChallenge)
	if w := from(e, "203.0.113.5", googleUA); w.Code != http.StatusOK || e.proxied(w) || !strings.Contains(w.Body.String(), "tm-") {
		t.Errorf("fake Googlebot with action challenge: %d", w.Code)
	}
	// DNS down: nobody gets in on the name alone, and nothing is remembered.
	dns.fail = true
	if w := from(e, "66.249.66.9", googleUA); e.proxied(w) {
		t.Errorf("DNS failure let a claimed Googlebot through: %d", w.Code)
	}
	dns.fail = false

	// Off (the default): the user agent alone decides, as before.
	e = newEnv(false, config.ActionBlock)
	if w := from(e, "203.0.113.5", googleUA); !e.proxied(w) {
		t.Errorf("check is off but the fake was stopped: %d", w.Code)
	}
}

// ---- a pass from another site -------------------------------------------------

func TestPassFromAnotherSite(t *testing.T) {
	e := fxNew(t, func(c *config.Config) {
		c.Sites = []config.Site{
			{Name: "API", Hosts: []string{"api.backend.test"}, OwnProtection: true, Protection: c.Protection},
			{Name: "Other", Hosts: []string{"other.test"}},
		}
		c.Sites[0].Protection.AcceptPassesFrom = []string{"default"}
	})
	token := func(cookie *http.Cookie) (int, string) {
		r := fxReq(http.MethodGet, PassURL)
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := e.do(r)
		var out struct{ Token, Header string }
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		if w.Code == 200 && (out.Header != PassHeader || w.Header().Get("Cache-Control") != "no-store") {
			t.Errorf("pass answer: header %q cache %q", out.Header, w.Header().Get("Cache-Control"))
		}
		return w.Code, out.Token
	}
	api := func(mod func(r *http.Request)) *httptest.ResponseRecorder {
		r := fxReq(http.MethodGet, "/v1/items")
		r.Host = "api.backend.test"
		r.Header.Set("Sec-Fetch-Mode", "cors")
		r.Header.Set("Origin", "https://example.com")
		if mod != nil {
			mod(r)
		}
		return e.do(r)
	}

	// No pass on the website: no token.
	if code, _ := token(nil); code != http.StatusUnauthorized {
		t.Fatalf("token without a pass: %d", code)
	}
	code, tok := token(e.pass(nil))
	if code != 200 || tok == "" {
		t.Fatalf("token with a pass: %d", code)
	}

	// Without it the API asks for a check, readable by the website's script.
	w := api(nil)
	if w.Code != http.StatusForbidden || w.Header().Get("Access-Control-Allow-Origin") != "https://example.com" {
		t.Errorf("API without a pass: %d %v", w.Code, w.Header())
	}
	// The same over plain http, where browsers send no Sec-Fetch-* headers:
	// a script must get JSON, not the checking page.
	w = api(func(r *http.Request) { r.Header.Del("Sec-Fetch-Mode"); r.Header.Del("Sec-Fetch-Dest") })
	if w.Code != http.StatusForbidden || !strings.HasPrefix(w.Header().Get("Content-Type"), "application/json") {
		t.Errorf("API without a pass over plain http: %d %s", w.Code, w.Header().Get("Content-Type"))
	}
	// With it the request reaches the app, and the app never sees the token.
	w = api(func(r *http.Request) { r.Header.Set(PassHeader, tok) })
	if !e.proxied(w) {
		t.Fatalf("API with the website's pass: %d %s", w.Code, w.Body.String())
	}
	if seen := e.up.last(); seen.header.Get(PassHeader) != "" {
		t.Error("the pass header reached the app")
	}
	// The token is tied to the visitor.
	if w := api(func(r *http.Request) { r.Header.Set(PassHeader, tok); r.RemoteAddr = "198.51.100.9:1" }); e.proxied(w) {
		t.Error("the token worked from another network")
	}
	// It is not a cookie, on either site.
	if w := e.get("/", &http.Cookie{Name: e.cookieName(), Value: tok}); e.proxied(w) {
		t.Error("the token worked as a pass cookie on the website")
	}
	if w := api(func(r *http.Request) { r.AddCookie(&http.Cookie{Name: e.cookieName(), Value: tok}) }); e.proxied(w) {
		t.Error("the token worked as a pass cookie on the API")
	}
	// A real pass cookie doesn't work in the header.
	if w := api(func(r *http.Request) { r.Header.Set(PassHeader, e.pass(nil).Value) }); e.proxied(w) {
		t.Error("a pass cookie value worked in the header")
	}
	// A site that isn't listed doesn't accept it, and hands out no tokens.
	r := fxReq(http.MethodGet, "/")
	r.Host = "other.test"
	r.Header.Set(PassHeader, tok)
	if w := e.do(r); e.proxied(w) {
		t.Error("an unlisted site accepted the token")
	}
	r = fxReq(http.MethodGet, PassURL)
	r.Host = "api.backend.test"
	if w := e.do(r); w.Code != http.StatusNotFound {
		t.Errorf("a site nobody trusts hands out tokens: %d", w.Code)
	}

	// The browser's CORS question passes without a pass, from the website only.
	pre := func(origin string) *httptest.ResponseRecorder {
		r := fxReq(http.MethodOptions, "/v1/items")
		r.Host = "api.backend.test"
		r.Header.Set("Origin", origin)
		r.Header.Set("Access-Control-Request-Method", "GET")
		r.Header.Set("Access-Control-Request-Headers", "x-tamamo-pass")
		return e.do(r)
	}
	if w := pre("https://example.com"); !e.proxied(w) {
		t.Errorf("preflight from the website: %d", w.Code)
	}
	if w := pre("https://other.test"); e.proxied(w) {
		t.Errorf("preflight from an unlisted site got through: %d", w.Code)
	}
}
