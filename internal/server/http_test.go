package server

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/foxgirlsorg/tamamo/internal/config"
	"github.com/foxgirlsorg/tamamo/internal/core"
)

// ---- full flow / difficulty ----------------------------------------------------------

func TestFullChallengeFlow(t *testing.T) {
	e := fxNew(t, nil)
	tok, c := e.issue("/docs?page=2")
	if e.up.count() != 0 {
		t.Fatal("challenged request was proxied")
	}
	w := e.verify(map[string]any{"token": tok, "nonce": fxSolve(t, c), "elapsed_ms": 42, "redirect": "/docs?page=2"})
	pass := e.passCookie(w)
	if w.Code != http.StatusOK || pass == nil {
		t.Fatalf("verify: %d %s", w.Code, w.Body)
	}
	if got := e.get("/docs?page=2", pass, &http.Cookie{Name: "app", Value: "1"}); !e.proxied(got) {
		t.Fatalf("pass rejected: %d", got.Code)
	}
	seen := e.up.last()
	if seen.uri != "/docs?page=2" || strings.Contains(seen.header.Get("Cookie"), e.cookieName()) || seen.header.Get("Cookie") != "app=1" {
		t.Errorf("upstream saw %q cookie %q", seen.uri, seen.header.Get("Cookie"))
	}
}

func TestDefaultDifficultyMatchesConfig(t *testing.T) {
	for i := 1; i <= 8; i++ {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			e := fxNew(t, func(c *config.Config) { c.Protection.Difficulty = i })
			if _, c := e.issue("/"); c.D != i {
				t.Errorf("difficulty %d, want %d", c.D, i)
			}
		})
	}
	e := fxNew(t, func(c *config.Config) {
		c.Rules = []config.Rule{{Name: "hard", Enabled: true, Action: config.ActionChallenge, Difficulty: 5, Match: config.Match{Paths: []string{"/hard/*"}}}}
	})
	if _, c := e.issue("/hard/x"); c.D != 5 {
		t.Errorf("rule difficulty %d, want 5", c.D)
	}
}

// ---- cookies -----------------------------------------------------------------------

func TestCookieSettings(t *testing.T) {
	for _, tc := range []struct {
		name       string
		mutate     func(c *config.Config)
		req        func(r *http.Request)
		wantName   string
		wantDomain string
		wantSecure bool
		wantExpiry time.Duration
	}{
		{name: "basic", wantName: "tamamo-pass", wantExpiry: 24 * time.Hour},
		{name: "domain", mutate: func(c *config.Config) { c.Protection.CookieDomain = "example.com" }, wantName: "tamamo-pass", wantDomain: "example.com", wantExpiry: 24 * time.Hour},
		{name: "custom name", mutate: func(c *config.Config) { c.Protection.CookieName = "my_pass-1" }, wantName: "my_pass-1", wantExpiry: 24 * time.Hour},
		{name: "custom expiration", mutate: func(c *config.Config) { c.Protection.PassHours = 2 }, wantName: "tamamo-pass", wantExpiry: 2 * time.Hour},
		{name: "secure behind https proxy", req: func(r *http.Request) { r.Header.Set("X-Forwarded-Proto", "https") }, wantName: "tamamo-pass", wantSecure: true, wantExpiry: 24 * time.Hour},
		{name: "secure over tls", req: func(r *http.Request) { r.TLS = &tls.ConnectionState{} }, wantName: "tamamo-pass", wantSecure: true, wantExpiry: 24 * time.Hour},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := fxNew(t, tc.mutate)
			c := e.challengeClaims()
			mods := []func(*http.Request){}
			if tc.req != nil {
				mods = append(mods, tc.req)
			}
			w := e.verify(map[string]any{"token": e.signChallenge(c), "nonce": fxSolve(t, c)}, mods...)
			if w.Code != http.StatusOK {
				t.Fatalf("verify: %d %s", w.Code, w.Body)
			}
			var ck *http.Cookie
			for _, x := range w.Result().Cookies() {
				if x.Name == tc.wantName {
					ck = x
				}
			}
			if ck == nil {
				t.Fatalf("cookie %q not set: %v", tc.wantName, w.Result().Cookies())
			}
			if !ck.HttpOnly || ck.SameSite != http.SameSiteLaxMode || ck.Path != "/" {
				t.Errorf("flags: %+v", ck)
			}
			if ck.Domain != tc.wantDomain {
				t.Errorf("domain %q, want %q", ck.Domain, tc.wantDomain)
			}
			if ck.Secure != tc.wantSecure {
				t.Errorf("secure %v, want %v", ck.Secure, tc.wantSecure)
			}
			if got := time.Until(ck.Expires); (got - tc.wantExpiry).Abs() > time.Minute {
				t.Errorf("expires in %s, want ~%s", got, tc.wantExpiry)
			}
			if ck.MaxAge != int(tc.wantExpiry/time.Second) {
				t.Errorf("max-age %d, want %d", ck.MaxAge, int(tc.wantExpiry/time.Second))
			}
		})
	}
}

func TestChallengeDoesNotClearAbsentCookie(t *testing.T) {
	e := fxNew(t, nil)
	w := e.get("/")
	if w.Code != http.StatusOK {
		t.Fatalf("want checking page, got %d", w.Code)
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == e.cookieName() {
			t.Errorf("challenge without a pass touched the pass cookie: %+v", c)
		}
	}
}

func TestInvalidCookieGetsFreshChallenge(t *testing.T) {
	e := fxNew(t, nil)
	good := e.pass(nil).Value
	payload, sig, _ := strings.Cut(good, ".")
	for name, v := range map[string]string{
		"wrong cookie":    "wrong cookie",
		"not a token":     "not-a-jwt",
		"tampered":        payload[:len(payload)-2] + "xx." + sig,
		"no signature":    payload,
		"challenge token": e.signChallenge(e.challengeClaims()),
		"other secret":    core.NewSigner("other", purposePass).Sign(core.PassClaims{D: 8, E: 1 << 40, B: e.bind(fxIP, fxUA), S: config.DefaultSiteID}),
	} {
		t.Run(name, func(t *testing.T) {
			r := fxReq(http.MethodGet, "/page")
			r.AddCookie(&http.Cookie{Name: e.cookieName(), Value: v})
			w := e.do(r)
			if w.Code != http.StatusOK || e.proxied(w) {
				t.Fatalf("got %d proxied=%v", w.Code, e.proxied(w))
			}
			found := false
			for _, tok := range fxTokenRe.FindAllString(w.Body.String(), -1) {
				var c core.ChallengeClaims
				if e.s.state().chal.Verify(tok, &c) == nil {
					found = true
				}
			}
			if !found {
				t.Error("no fresh challenge in the page")
			}
		})
	}
}

func TestExpiredPassRechallenges(t *testing.T) {
	e := fxNew(t, nil)
	if w := e.get("/", e.pass(func(c *core.PassClaims) { c.E = e.s.now().Add(-time.Second).Unix() })); e.proxied(w) {
		t.Error("expired pass accepted")
	}
	if w := e.get("/", e.pass(nil)); !e.proxied(w) {
		t.Errorf("valid pass rejected: %d", w.Code)
	}
	// Time moves past the pass expiry.
	ck := e.pass(nil)
	e.s.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	if w := e.get("/", ck); e.proxied(w) {
		t.Error("pass accepted after it expired")
	}
}

func TestPassForAnotherSiteRejected(t *testing.T) {
	e := fxNew(t, func(c *config.Config) {
		c.Sites = []config.Site{{Name: "Other", Hosts: []string{"other.test"}}}
	})
	siteID := e.s.mgr.Get().Sites[0].ID
	req := func(host string, ck *http.Cookie) *http.Request {
		r := fxReq(http.MethodGet, "/")
		r.Host = host
		r.AddCookie(ck)
		return r
	}
	defPass := e.pass(nil)
	sitePass := e.pass(func(c *core.PassClaims) { c.S = siteID })
	if w := e.do(req("other.test", defPass)); e.proxied(w) {
		t.Error("default-site pass accepted on other.test")
	}
	if w := e.do(req("example.com", sitePass)); e.proxied(w) {
		t.Error("other.test pass accepted on the default site")
	}
	if w := e.do(req("other.test", sitePass)); !e.proxied(w) {
		t.Errorf("site pass rejected on its own site: %d", w.Code)
	}
	if w := e.do(req("OTHER.test:8923", sitePass)); !e.proxied(w) {
		t.Errorf("site pass rejected with port / upper-case host: %d", w.Code)
	}
	// A challenge issued for one site cannot be redeemed on another.
	c := e.challengeClaims()
	w := e.verify(map[string]any{"token": e.signChallenge(c), "nonce": fxSolve(t, c)}, func(r *http.Request) { r.Host = "other.test" })
	if w.Code != http.StatusForbidden || e.passCookie(w) != nil {
		t.Errorf("default-site challenge redeemed on other.test: %d", w.Code)
	}
}

func TestPassCannotTransferToHarderRule(t *testing.T) {
	e := fxNew(t, func(c *config.Config) {
		c.Rules = []config.Rule{{Name: "hard", Enabled: true, Action: config.ActionChallenge, Difficulty: 5, Match: config.Match{Paths: []string{"/hard/*"}}}}
	})
	easy := e.pass(func(c *core.PassClaims) { c.D = 1 })
	if w := e.get("/easy", easy); !e.proxied(w) {
		t.Errorf("difficulty-1 pass rejected on a difficulty-1 page: %d", w.Code)
	}
	if w := e.get("/hard/x", easy); e.proxied(w) {
		t.Error("difficulty-1 pass accepted by a difficulty-5 rule")
	}
	hard := e.pass(func(c *core.PassClaims) { c.D = 5 })
	if w := e.get("/hard/x", hard); !e.proxied(w) {
		t.Errorf("difficulty-5 pass rejected: %d", w.Code)
	}
}

func TestPassBoundToClient(t *testing.T) {
	e := fxNew(t, nil)
	ck := e.pass(nil)
	from := func(ip, ua string) bool {
		r := fxReq(http.MethodGet, "/")
		r.RemoteAddr = ip + ":1"
		r.Header.Set("User-Agent", ua)
		r.AddCookie(ck)
		return e.proxied(e.do(r))
	}
	if !from("192.0.2.99", fxUA) {
		t.Error("pass rejected inside the same /24")
	}
	if from("198.51.100.1", fxUA) {
		t.Error("pass accepted from another network")
	}
	if from(fxIP, "curl/8") {
		t.Error("pass accepted with another user agent")
	}
	e2 := fxNew(t, func(c *config.Config) { c.Protection.BindIP = false; c.Protection.BindUserAgent = false })
	ck2 := e2.pass(nil)
	r := fxReq(http.MethodGet, "/")
	r.RemoteAddr = "198.51.100.1:1"
	r.AddCookie(ck2)
	if !e2.proxied(e2.do(r)) {
		t.Error("unbound pass rejected from another network")
	}
}

func TestRotatedSecretInvalidatesPass(t *testing.T) {
	e := fxNew(t, nil)
	ck := e.pass(nil)
	if w := e.get("/", ck); !e.proxied(w) {
		t.Fatalf("pass rejected: %d", w.Code)
	}
	if len(e.s.mgr.Get().Secret) < 32 {
		t.Errorf("signing secret is only %d characters", len(e.s.mgr.Get().Secret))
	}
	if err := e.s.mgr.RotateSecret(); err != nil {
		t.Fatal(err)
	}
	if w := e.get("/", ck); e.proxied(w) {
		t.Error("pass signed with the old secret still accepted")
	}
}

// ---- HTTP behavior --------------------------------------------------------------------

func fxUAConfig(c *config.Config) {
	c.Protection.DefaultAction = config.ActionAllow
	c.Rules = []config.Rule{
		fxRule("allow", config.ActionAllow, config.Match{UserAgents: []string{"ALLOW"}}),
		fxRule("deny", config.ActionBlock, config.Match{UserAgents: []string{"DENY"}}),
		fxRule("challenge", config.ActionChallenge, config.Match{UserAgents: []string{"CHALLENGE"}}),
	}
}

func TestStatusCodes(t *testing.T) {
	e := fxNew(t, fxUAConfig)
	for _, tc := range []struct {
		ua, mode string
		code     int
		ct       string
	}{
		{"ALLOW", "navigate", 200, ""},
		{"DENY", "navigate", 403, "text/html"},
		{"CHALLENGE", "navigate", 200, "text/html"},
		{"CHALLENGE", "cors", 403, "application/json"},
		{"DENY", "cors", 403, "text/html"},
	} {
		r := fxReq(http.MethodGet, "/")
		r.Header.Set("User-Agent", tc.ua)
		r.Header.Set("Sec-Fetch-Mode", tc.mode)
		w := e.do(r)
		if w.Code != tc.code || (tc.ct != "" && !strings.HasPrefix(w.Header().Get("Content-Type"), tc.ct)) {
			t.Errorf("%s/%s: %d %s", tc.ua, tc.mode, w.Code, w.Header().Get("Content-Type"))
		}
		if tc.ua == "ALLOW" && !e.proxied(w) {
			t.Error("ALLOW not proxied")
		}
		if tc.ua != "ALLOW" && e.proxied(w) {
			t.Errorf("%s proxied", tc.ua)
		}
	}
}

func TestNoCacheAndNoindexOnPages(t *testing.T) {
	e := fxNew(t, fxUAConfig)
	for _, ua := range []string{"DENY", "CHALLENGE"} {
		r := fxReq(http.MethodGet, "/")
		r.Header.Set("User-Agent", ua)
		w := e.do(r)
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("%s: Cache-Control %q", ua, w.Header().Get("Cache-Control"))
		}
		if !strings.Contains(w.Header().Get("X-Robots-Tag"), "noindex") {
			t.Errorf("%s: X-Robots-Tag %q", ua, w.Header().Get("X-Robots-Tag"))
		}
		if w.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s: missing nosniff", ua)
		}
	}
	r := fxReq(http.MethodGet, "/")
	r.Header.Set("User-Agent", "CHALLENGE")
	if w := e.do(r); !strings.Contains(strings.Join(w.Header().Values("Vary"), ","), "Cookie") {
		t.Errorf("challenge page does not vary on Cookie: %v", w.Header())
	}
	r.Header.Set("Sec-Fetch-Mode", "cors")
	if w := e.do(r); w.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("JSON challenge cacheable: %q", w.Header().Get("Cache-Control"))
	}
	// Error page (no upstream).
	if err := e.s.mgr.Update(func(c *config.Config) error { c.Server.Target = ""; return nil }); err != nil {
		t.Fatal(err)
	}
	r = fxReq(http.MethodGet, "/")
	r.Header.Set("User-Agent", "ALLOW")
	w := e.do(r)
	if w.Code != http.StatusBadGateway || w.Header().Get("Cache-Control") != "no-store" || !strings.Contains(w.Header().Get("X-Robots-Tag"), "noindex") {
		t.Errorf("error page: %d %v", w.Code, w.Header())
	}
}

func TestHEADRequests(t *testing.T) {
	e := fxNew(t, fxUAConfig)
	for _, tc := range []struct {
		ua   string
		code int
	}{{"CHALLENGE", 200}, {"DENY", 403}} {
		r := fxReq(http.MethodHead, "/")
		r.Header.Set("User-Agent", tc.ua)
		w := e.do(r)
		if w.Code != tc.code || w.Body.Len() != 0 || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/html") {
			t.Errorf("HEAD %s: %d len=%d %s", tc.ua, w.Code, w.Body.Len(), w.Header().Get("Content-Type"))
		}
	}
	r := fxReq(http.MethodHead, "/")
	r.Header.Set("User-Agent", "CHALLENGE")
	r.Header.Set("Sec-Fetch-Mode", "cors")
	if w := e.do(r); w.Code != 403 || w.Body.Len() != 0 {
		t.Errorf("HEAD JSON challenge: %d len=%d", w.Code, w.Body.Len())
	}
	if w := e.do(fxReq(http.MethodHead, HealthURL)); w.Code != 200 {
		t.Errorf("HEAD health: %d", w.Code)
	}
	r = fxReq(http.MethodHead, "/x")
	r.Header.Set("User-Agent", "ALLOW")
	if e.do(r); e.up.count() != 1 {
		t.Errorf("HEAD allow not proxied")
	}
}

func TestNonNavigationRequestsGetJSON(t *testing.T) {
	e := fxNew(t, nil)
	for name, hdr := range map[string]map[string]string{
		"fetch cors":       {"Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty"},
		"fetch no-cors":    {"Sec-Fetch-Mode": "no-cors", "Sec-Fetch-Dest": "image"},
		"same-origin":      {"Sec-Fetch-Mode": "same-origin", "Sec-Fetch-Dest": "empty"},
		"xhr":              {"X-Requested-With": "XMLHttpRequest"},
		"websocket":        {"Upgrade": "websocket", "Connection": "Upgrade", "Sec-Fetch-Mode": ""},
		"script dest only": {"Sec-Fetch-Mode": "", "Sec-Fetch-Dest": "script"},
	} {
		r := fxReq(http.MethodGet, "/api/data")
		for k, v := range hdr {
			if v == "" {
				r.Header.Del(k)
			} else {
				r.Header.Set(k, v)
			}
		}
		w := e.do(r)
		if w.Code != http.StatusForbidden || !strings.HasPrefix(w.Header().Get("Content-Type"), "application/json") ||
			!strings.Contains(w.Body.String(), "challenge_required") || w.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s: %d %s %s", name, w.Code, w.Header().Get("Content-Type"), w.Body)
		}
	}
	for name, hdr := range map[string]map[string]string{
		"no fetch metadata": {"Sec-Fetch-Mode": "", "Sec-Fetch-Dest": ""},
		"iframe":            {"Sec-Fetch-Mode": "nested-navigate", "Sec-Fetch-Dest": "iframe"},
	} {
		r := fxReq(http.MethodGet, "/page")
		for k, v := range hdr {
			if v == "" {
				r.Header.Del(k)
			} else {
				r.Header.Set(k, v)
			}
		}
		if w := e.do(r); w.Code != http.StatusOK || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/html") {
			t.Errorf("%s: %d %s", name, w.Code, w.Header().Get("Content-Type"))
		}
	}
	if e.up.count() != 0 {
		t.Errorf("challenged requests were proxied")
	}
}

func TestNonGETRequests(t *testing.T) {
	e := fxNew(t, func(c *config.Config) {
		c.Rules = []config.Rule{fxRule("no delete", config.ActionBlock, config.Match{Methods: []string{"delete", "PUT"}})}
	})
	if w := e.do(fxReq(http.MethodPost, "/form")); w.Code != http.StatusOK || e.proxied(w) {
		t.Errorf("POST navigation without pass: %d", w.Code)
	}
	r := fxReq(http.MethodPost, "/form")
	r.Header.Set("Sec-Fetch-Mode", "cors")
	if w := e.do(r); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "challenge_required") {
		t.Errorf("POST fetch without pass: %d", w.Code)
	}
	for _, m := range []string{http.MethodDelete, http.MethodPut} {
		r := fxReq(m, "/x")
		r.AddCookie(e.pass(nil))
		if w := e.do(r); w.Code != http.StatusForbidden || e.proxied(w) {
			t.Errorf("%s with pass: %d", m, w.Code)
		}
	}
	if e.up.count() != 0 {
		t.Fatal("unverified requests were proxied")
	}
	body := strings.Repeat("x", 128<<10)
	r = httptest.NewRequest(http.MethodPost, "/upload", strings.NewReader(body))
	r.RemoteAddr = fxIP + ":5555"
	r.Header.Set("User-Agent", fxUA)
	r.Header.Set("Content-Type", "application/octet-stream")
	r.AddCookie(e.pass(nil))
	if w := e.do(r); !e.proxied(w) {
		t.Fatalf("POST with pass: %d", w.Code)
	}
	if got := e.up.last(); string(got.body) != body {
		t.Errorf("upload changed: %d bytes", len(got.body))
	}
}

// ---- nginx auth_request / render-only -------------------------------------------------

func TestAuthRequestResponses(t *testing.T) {
	e := fxNew(t, fxUAConfig)
	for _, tc := range []struct {
		ua   string
		code int
	}{{"ALLOW", 204}, {"DENY", 403}, {"CHALLENGE", 401}} {
		for _, m := range []string{http.MethodGet, http.MethodHead} {
			r := fxReq(m, AuthURL)
			r.Header.Set("User-Agent", tc.ua)
			r.Header.Set("X-Original-URI", "/test")
			w := e.do(r)
			if w.Code != tc.code || w.Body.Len() != 0 || w.Header().Get("Cache-Control") != "no-store" {
				t.Errorf("%s %s: %d len=%d cache=%q", m, tc.ua, w.Code, w.Body.Len(), w.Header().Get("Cache-Control"))
			}
			if len(w.Result().Cookies()) != 0 {
				t.Errorf("%s %s: auth response sets cookies", m, tc.ua)
			}
		}
	}
	// X-Original-Method drives method rules.
	e2 := fxNew(t, func(c *config.Config) {
		c.Protection.DefaultAction = config.ActionAllow
		c.Rules = []config.Rule{fxRule("no post", config.ActionBlock, config.Match{Methods: []string{"POST"}})}
	})
	r := fxReq(http.MethodGet, AuthURL)
	r.Header.Set("X-Original-URI", "/x")
	r.Header.Set("X-Original-Method", "POST")
	if w := e2.do(r); w.Code != 403 {
		t.Errorf("X-Original-Method POST: %d", w.Code)
	}
	// A pass works through auth_request; a pass for another site doesn't.
	e3 := fxNew(t, func(c *config.Config) { c.Sites = []config.Site{{Name: "Other", Hosts: []string{"other.test"}}} })
	for host, want := range map[string]int{"example.com": 204, "other.test": 401} {
		r := fxReq(http.MethodGet, AuthURL)
		r.Host = host
		r.Header.Set("X-Original-URI", "/page")
		r.AddCookie(e3.pass(nil))
		if w := e3.do(r); w.Code != want {
			t.Errorf("auth pass on %s: %d, want %d", host, w.Code, want)
		}
	}
	if e.up.count()+e2.up.count()+e3.up.count() != 0 {
		t.Error("auth_request requests were proxied")
	}
}

func TestRenderOnlyPages(t *testing.T) {
	e := fxNew(t, fxUAConfig)
	for _, tc := range []struct {
		ua   string
		code int
	}{{"DENY", 403}, {"CHALLENGE", 200}} {
		r := fxReq(http.MethodGet, "/ignored")
		r.Header.Set("User-Agent", tc.ua)
		r.Header.Set(RenderHeader, "1")
		r.Header.Set("X-Original-URI", "/docs")
		w := e.do(r)
		if w.Code != tc.code || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/html") || w.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("%s: %d %v", tc.ua, w.Code, w.Header())
		}
	}
	if e.up.count() != 0 {
		t.Error("render-only requests were proxied")
	}
	// Only the exact value "1" switches render-only mode on.
	r := fxReq(http.MethodGet, "/x")
	r.Header.Set("User-Agent", "ALLOW")
	r.Header.Set(RenderHeader, "true")
	if w := e.do(r); !e.proxied(w) {
		t.Errorf("render header %q changed behavior: %d", "true", w.Code)
	}
}

// ---- client IP ---------------------------------------------------------------------------

func TestClientIPSpoofingCannotBypassIPRules(t *testing.T) {
	for _, tc := range []struct {
		name    string
		source  string
		trusted []string
		peer    string
		hdr     map[string]string
		allowed bool
	}{
		{"remote ignores XFF", "remote", nil, "203.0.113.5", map[string]string{"X-Forwarded-For": "10.0.0.1", "X-Real-IP": "10.0.0.1", "CF-Connecting-IP": "10.0.0.1"}, false},
		{"untrusted peer XFF", "x-forwarded-for", []string{"192.0.2.0/24"}, "203.0.113.5", map[string]string{"X-Forwarded-For": "10.0.0.1"}, false},
		{"attacker prepends XFF", "x-forwarded-for", []string{"192.0.2.0/24"}, fxIP, map[string]string{"X-Forwarded-For": "10.0.0.1, 203.0.113.9"}, false},
		{"trusted proxy appends", "x-forwarded-for", []string{"192.0.2.0/24"}, fxIP, map[string]string{"X-Forwarded-For": "203.0.113.9, 10.0.0.1"}, true},
		{"untrusted peer X-Real-IP", "x-real-ip", []string{"192.0.2.0/24"}, "203.0.113.5", map[string]string{"X-Real-IP": "10.0.0.1"}, false},
		{"trusted peer X-Real-IP", "x-real-ip", []string{"192.0.2.0/24"}, fxIP, map[string]string{"X-Real-IP": "10.0.0.1"}, true},
		{"untrusted peer CF", "cf-connecting-ip", []string{"192.0.2.0/24"}, "203.0.113.5", map[string]string{"CF-Connecting-IP": "10.0.0.1"}, false},
		{"trusted peer CF", "cf-connecting-ip", []string{"192.0.2.0/24"}, fxIP, map[string]string{"CF-Connecting-IP": "10.0.0.1"}, true},
		{"garbage XFF", "x-forwarded-for", []string{"192.0.2.0/24"}, fxIP, map[string]string{"X-Forwarded-For": "10.0.0.1, nonsense"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := fxNew(t, func(c *config.Config) {
				c.Server.IPSource = tc.source
				c.Server.TrustedProxies = tc.trusted
				c.Protection.DefaultAction = config.ActionBlock
				c.Rules = []config.Rule{fxRule("internal", config.ActionAllow, config.Match{IPs: []string{"10.0.0.0/8"}})}
			})
			r := fxReq(http.MethodGet, "/")
			r.RemoteAddr = tc.peer + ":1234"
			for k, v := range tc.hdr {
				r.Header.Set(k, v)
			}
			w := e.do(r)
			if e.proxied(w) != tc.allowed {
				t.Fatalf("proxied=%v, want %v (status %d)", e.proxied(w), tc.allowed, w.Code)
			}
			if tc.allowed {
				if got := e.up.last().header.Get("X-Real-IP"); got != "10.0.0.1" {
					t.Errorf("upstream X-Real-IP %q", got)
				}
			}
		})
	}
}

func TestBlockByClientIPBehindProxy(t *testing.T) {
	e := fxNew(t, func(c *config.Config) {
		c.Server.IPSource = "x-forwarded-for"
		c.Server.TrustedProxies = []string{"192.0.2.0/24", "10.0.0.0/8"}
		c.Protection.DefaultAction = config.ActionAllow
		c.Rules = []config.Rule{fxRule("bad", config.ActionBlock, config.Match{IPs: []string{"198.51.100.7"}})}
	})
	for _, xff := range []string{"198.51.100.7", "1.2.3.4, 198.51.100.7", "198.51.100.7, 10.0.0.3", "6.6.6.6,198.51.100.7, 10.1.1.1"} {
		r := fxReq(http.MethodGet, "/")
		r.Header.Set("X-Forwarded-For", xff)
		if w := e.do(r); w.Code != http.StatusForbidden {
			t.Errorf("XFF %q: %d", xff, w.Code)
		}
	}
}

func TestDownstreamHeadersAreAuthoritative(t *testing.T) {
	e := fxNew(t, func(c *config.Config) { c.Protection.DefaultAction = config.ActionAllow })
	r := fxReq(http.MethodGet, "/")
	r.Header["X-Real-Ip"] = []string{"6.6.6.6", "7.7.7.7"}
	r.Header.Set("X-Forwarded-For", "6.6.6.6")
	r.Header.Set("Forwarded", "for=6.6.6.6;proto=https")
	r.Header.Set("Connection", "keep-alive, X-Real-IP")
	if w := e.do(r); !e.proxied(w) {
		t.Fatalf("not proxied: %d", w.Code)
	}
	h := e.up.last().header
	if got := h.Values("X-Real-Ip"); len(got) != 1 || got[0] != fxIP {
		t.Errorf("upstream X-Real-IP %q, want %q", got, fxIP)
	}
	xff := h.Get("X-Forwarded-For")
	if strings.Contains(xff, "6.6.6.6") || strings.HasPrefix(xff, ",") || strings.Contains(xff, ",,") || !strings.Contains(xff, fxIP) {
		t.Errorf("upstream X-Forwarded-For %q", xff)
	}
	if f := h.Get("Forwarded"); strings.Contains(f, "6.6.6.6") {
		t.Errorf("spoofed Forwarded header passed: %q", f)
	}
}

// ---- reverse proxy -------------------------------------------------------------------------

func TestReverseProxy(t *testing.T) {
	for _, preserve := range []bool{false, true} {
		e := fxNew(t, func(c *config.Config) {
			c.Protection.DefaultAction = config.ActionAllow
			c.Server.PreserveHost = preserve
		})
		r := fxReq(http.MethodGet, "/foo/bar?baz=qux")
		r.Host = "site.example.com"
		e.do(r)
		got := e.up.last()
		if got.uri != "/foo/bar?baz=qux" {
			t.Errorf("preserve=%v: path %q", preserve, got.uri)
		}
		wantHost := strings.TrimPrefix(e.upURL, "http://")
		if preserve {
			wantHost = "site.example.com"
		}
		if got.host != wantHost {
			t.Errorf("preserve=%v: host %q, want %q", preserve, got.host, wantHost)
		}
		if xfh := got.header.Get("X-Forwarded-Host"); xfh != "site.example.com" {
			t.Errorf("X-Forwarded-Host %q", xfh)
		}
	}
	t.Run("semicolon-delimited query is preserved", func(t *testing.T) {
		e := fxNew(t, func(c *config.Config) { c.Protection.DefaultAction = config.ActionAllow })
		e.do(fxReq(http.MethodGet, "/?p=testing.git;a=summary"))
		got := e.up.last().uri
		fxCheck(t, got != "/?p=testing.git;a=summary",
			"query %q reached the upstream as %q: httputil.ReverseProxy in Rewrite mode drops query parameters containing ';' (gitweb-style URLs break)", "p=testing.git;a=summary", got)
	})
}

// ---- robots / well-known --------------------------------------------------------------------

func TestRobotsAndWellKnownAllowed(t *testing.T) {
	e := fxNew(t, func(c *config.Config) {
		c.Protection.DefaultAction = config.ActionBlock
		c.Rules = []config.Rule{fxRule("well-known", config.ActionAllow, config.Match{Paths: []string{"/robots.txt", "/.well-known/*", "/favicon.ico"}})}
	})
	for _, p := range []string{"/robots.txt", "/robots.txt?x=1", "/.well-known/security.txt", "/.well-known/acme-challenge/abc", "/favicon.ico"} {
		if w := e.get(p); !e.proxied(w) {
			t.Errorf("%s: %d", p, w.Code)
		}
	}
	for _, p := range []string{"/robots.txt.bak", "/x/robots.txt", "/.well-known", "/favicon.ico/x", "/"} {
		if w := e.get(p); w.Code != http.StatusForbidden {
			t.Errorf("%s: %d", p, w.Code)
		}
	}
	t.Run("traversal out of well-known", func(t *testing.T) {
		before := e.up.count()
		e.get("/.well-known/../admin")
		fxCheck(t, e.up.count() != before,
			"/.well-known/../admin is allowed by the /.well-known/* rule and proxied, although it addresses /admin (dot segments are not normalized before rule matching)")
	})
}

// ---- stats --------------------------------------------------------------------------------

func TestStatsCounting(t *testing.T) {
	e := fxNew(t, fxUAConfig)
	do := func(ua, mode string, cookies ...*http.Cookie) {
		r := fxReq(http.MethodGet, "/p")
		r.Header.Set("User-Agent", ua)
		r.Header.Set("Sec-Fetch-Mode", mode)
		for _, c := range cookies {
			r.AddCookie(c)
		}
		e.do(r)
	}
	do("ALLOW", "navigate")
	do("other", "navigate")
	do("DENY", "navigate")
	do("DENY", "navigate")
	do("CHALLENGE", "navigate")
	do("CHALLENGE", "cors")
	e.verify(map[string]any{"token": "x.y", "nonce": "1"})
	c := e.challengeClaims()
	e.verify(map[string]any{"token": e.signChallenge(c), "nonce": fxSolve(t, c)})
	pass := e.pass(func(p *core.PassClaims) { p.B = e.bind(fxIP, "CHALLENGE") })
	do("CHALLENGE", "navigate", pass)

	got := e.totals()
	want := struct{ allowed, blocked, challenged, failed, solved, passed int64 }{2, 2, 2, 1, 1, 1}
	if got.Allowed != want.allowed || got.Blocked != want.blocked || got.Challenged != want.challenged ||
		got.Failed != want.failed || got.Solved != want.solved || got.Passed != want.passed {
		t.Errorf("totals %+v, want %+v", got, want)
	}
	if got.Requests != 7 {
		t.Errorf("requests %d, want 7", got.Requests)
	}
	snap := e.st.Snapshot("")
	found := false
	for _, n := range snap.TopRules {
		if n.Name == "deny" && n.Count == 2 {
			found = true
		}
	}
	if !found {
		t.Errorf("rule \"deny\" not counted: %+v", snap.TopRules)
	}
}

func TestForwardAuth(t *testing.T) {
	e := fxNew(t, fxUAConfig)
	for _, tc := range []struct {
		ua   string
		code int
		html bool
	}{{"ALLOW", 204, false}, {"DENY", 403, true}, {"CHALLENGE", 401, true}} {
		r := fxReq(http.MethodGet, ForwardAuthURL)
		r.Header.Set("User-Agent", tc.ua)
		r.Header.Set("X-Forwarded-Uri", "/docs?page=2")
		r.Header.Set("X-Forwarded-Method", "GET")
		w := e.do(r)
		isHTML := strings.HasPrefix(w.Header().Get("Content-Type"), "text/html")
		if w.Code != tc.code || isHTML != tc.html || w.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("%s: %d html=%v %v", tc.ua, w.Code, isHTML, w.Header())
		}
		if tc.ua == "CHALLENGE" && !strings.Contains(w.Body.String(), "/docs?page=2") {
			t.Error("checking page doesn't send the visitor back to the page they asked for")
		}
	}
	// The visitor's own X-Original-* headers reach this endpoint untouched
	// and must not choose the page the answer is about.
	es := fxNew(t, func(c *config.Config) {
		c.Protection.DefaultAction = config.ActionAllow
		c.Rules = []config.Rule{fxRule("admin", config.ActionBlock, config.Match{Paths: []string{"/admin/*"}})}
	})
	rs := fxReq(http.MethodGet, ForwardAuthURL)
	rs.Header.Set("X-Forwarded-Uri", "/admin/secret")
	rs.Header.Set("X-Original-URI", "/public")
	if w := es.do(rs); w.Code != 403 {
		t.Errorf("spoofed X-Original-URI let /admin/secret through: %d", w.Code)
	}
	// X-Forwarded-Method drives method rules.
	e2 := fxNew(t, func(c *config.Config) {
		c.Protection.DefaultAction = config.ActionAllow
		c.Rules = []config.Rule{fxRule("no post", config.ActionBlock, config.Match{Methods: []string{"POST"}})}
	})
	r := fxReq(http.MethodGet, ForwardAuthURL)
	r.Header.Set("X-Forwarded-Uri", "/x")
	r.Header.Set("X-Forwarded-Method", "POST")
	if w := e2.do(r); w.Code != 403 {
		t.Errorf("X-Forwarded-Method POST: %d", w.Code)
	}
	// X-Forwarded-Host picks the site only when proxy headers are trusted.
	for _, tc := range []struct {
		source string
		want   int
	}{{"remote", 204}, {"x-forwarded-for", 401}} {
		e3 := fxNew(t, func(c *config.Config) {
			c.Server.IPSource = tc.source
			c.Sites = []config.Site{{Name: "Other", Hosts: []string{"other.test"}}}
		})
		r := fxReq(http.MethodGet, ForwardAuthURL)
		r.Host = "tamamo:8923"
		r.Header.Set("X-Forwarded-Host", "other.test")
		r.Header.Set("X-Forwarded-Uri", "/page")
		r.AddCookie(e3.pass(nil))
		if w := e3.do(r); w.Code != tc.want {
			t.Errorf("ip_source %s: pass for the default site on other.test: %d, want %d", tc.source, w.Code, tc.want)
		}
	}
	if e.up.count()+e2.up.count() != 0 {
		t.Error("forward-auth requests were proxied")
	}
}
