package server

// Shared helpers for the end-to-end tests (http_test.go, security_test.go). They
// build their own configuration and rules so they don't depend on Tamamo's
// default rule list or on the exact HTML of the checking page.

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/foxgirlsorg/tamamo/internal/assets"
	"github.com/foxgirlsorg/tamamo/internal/config"
	"github.com/foxgirlsorg/tamamo/internal/core"
	"github.com/foxgirlsorg/tamamo/internal/stats"
)

const (
	fxUA   = "Mozilla/5.0 (X11; Linux x86_64) TamamoTest/1.0"
	fxIP   = "192.0.2.10"
	fxBody = "upstream says hi"
)

type fxSeen struct {
	host   string
	uri    string
	header http.Header
	body   []byte
}

type fxUpstream struct {
	mu   sync.Mutex
	reqs []fxSeen
}

func (u *fxUpstream) count() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return len(u.reqs)
}

func (u *fxUpstream) last() fxSeen {
	u.mu.Lock()
	defer u.mu.Unlock()
	if len(u.reqs) == 0 {
		return fxSeen{}
	}
	return u.reqs[len(u.reqs)-1]
}

type fxEnv struct {
	t     *testing.T
	s     *Server
	st    *stats.Stats
	up    *fxUpstream
	upURL string
}

// fxNew builds a Server in front of a recording upstream. The base config
// has difficulty 1, no rules, default action "challenge", IP + UA binding,
// unlimited failures and ip_source "remote"; mutate adjusts it further.
func fxNew(t *testing.T, mutate func(c *config.Config)) *fxEnv {
	t.Helper()
	up := &fxUpstream{}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		up.mu.Lock()
		up.reqs = append(up.reqs, fxSeen{host: r.Host, uri: r.URL.RequestURI(), header: r.Header.Clone(), body: b})
		up.mu.Unlock()
		_, _ = io.WriteString(w, fxBody)
	}))
	t.Cleanup(ts.Close)

	dir := t.TempDir()
	t.Setenv("TAMAMO_TARGET", "")
	t.Setenv("TAMAMO_IP_SOURCE", "")
	mgr, err := config.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := mgr.Update(func(c *config.Config) error {
		c.Server.Target = ts.URL
		c.Server.IPSource = "remote"
		c.Server.TrustedProxies = nil
		c.Server.PreserveHost = false
		c.Server.AuthEndpoints = "on"
		c.Protection.Enabled = true
		c.Protection.Difficulty = 1
		c.Stats.Enabled = true
		c.Protection.DefaultAction = config.ActionChallenge
		c.Protection.BindIP = true
		c.Protection.BindUserAgent = true
		c.Protection.MaxFailures = 0
		c.Protection.PassHours = 24
		c.Protection.ChallengeMinutes = 30
		c.Protection.CookieName = "tamamo-pass"
		c.Protection.CookieDomain = ""
		c.Rules = []config.Rule{}
		c.Sites = []config.Site{}
		c.Modules = []config.ModuleConfig{}
		if mutate != nil {
			mutate(c)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	st, err := stats.New(dir, mgr)
	if err != nil {
		t.Fatal(err)
	}
	as, err := assets.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	return &fxEnv{t: t, s: New(mgr, st, as), st: st, up: up, upURL: ts.URL}
}

func fxRule(name, action string, m config.Match) config.Rule {
	return config.Rule{Name: name, Enabled: true, Action: action, Match: m}
}

// fxReq builds a top-level browser navigation from fxIP with fxUA.
func fxReq(method, target string) *http.Request {
	r := httptest.NewRequest(method, target, nil)
	r.RemoteAddr = fxIP + ":5555"
	r.Header.Set("User-Agent", fxUA)
	r.Header.Set("Sec-Fetch-Mode", "navigate")
	r.Header.Set("Sec-Fetch-Dest", "document")
	return r
}

func (e *fxEnv) do(r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	e.s.ServeHTTP(w, r)
	return w
}

func (e *fxEnv) get(target string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	r := fxReq(http.MethodGet, target)
	for _, c := range cookies {
		r.AddCookie(c)
	}
	return e.do(r)
}

func (e *fxEnv) proxied(w *httptest.ResponseRecorder) bool {
	return w.Body.String() == fxBody
}

func (e *fxEnv) cookieName() string { return e.s.mgr.Get().Protection.CookieName }

func (e *fxEnv) bind(ip, ua string) string {
	p := e.s.mgr.Get().Protection
	return core.BindHash(netip.MustParseAddr(ip), ua, p.BindIP, p.BindUserAgent)
}

// pass mints a valid pass cookie for fxIP/fxUA on the default site.
func (e *fxEnv) pass(mod func(c *core.PassClaims)) *http.Cookie {
	now := e.s.now()
	c := core.PassClaims{D: 8, E: now.Add(time.Hour).Unix(), I: now.Unix(), B: e.bind(fxIP, fxUA), S: config.DefaultSiteID}
	if mod != nil {
		mod(&c)
	}
	return &http.Cookie{Name: e.cookieName(), Value: e.s.state().pass.Sign(c)}
}

// challengeClaims returns valid claims for a fresh difficulty-1 challenge
// issued to fxIP/fxUA on the default site.
func (e *fxEnv) challengeClaims() core.ChallengeClaims {
	return core.ChallengeClaims{
		R: core.NewRandom(), D: 1, E: e.s.now().Add(5 * time.Minute).Unix(),
		B: e.bind(fxIP, fxUA), S: config.DefaultSiteID,
	}
}

func (e *fxEnv) signChallenge(c core.ChallengeClaims) string { return e.s.state().chal.Sign(c) }

var fxTokenRe = regexp.MustCompile(`[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{43}`)

// issue fetches target, expects a checking page and returns its token and
// the claims, verified with the server's challenge signer.
func (e *fxEnv) issue(target string) (string, core.ChallengeClaims) {
	e.t.Helper()
	w := e.get(target)
	if w.Code != http.StatusOK || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/html") {
		e.t.Fatalf("GET %s: want checking page, got %d %s", target, w.Code, w.Header().Get("Content-Type"))
	}
	for _, tok := range fxTokenRe.FindAllString(w.Body.String(), -1) {
		var c core.ChallengeClaims
		if e.s.state().chal.Verify(tok, &c) == nil {
			return tok, c
		}
	}
	e.t.Fatalf("no valid challenge token in the checking page for %s", target)
	return "", core.ChallengeClaims{}
}

func fxSolve(t *testing.T, c core.ChallengeClaims) string {
	t.Helper()
	for n := 0; n < 50_000_000; n++ {
		if _, ok := core.CheckPoW(c.R, strconv.Itoa(n), c.D); ok {
			return strconv.Itoa(n)
		}
	}
	t.Fatal("no solution")
	return ""
}

// fxWrongNonce returns a well-formed nonce that does not solve c.
func fxWrongNonce(c core.ChallengeClaims) string {
	for n := 0; ; n++ {
		if _, ok := core.CheckPoW(c.R, strconv.Itoa(n), c.D); !ok {
			return strconv.Itoa(n)
		}
	}
}

// verify posts body (a string is sent as-is, anything else as JSON) to the
// verify endpoint from fxIP/fxUA. mods can adjust the request.
func (e *fxEnv) verify(body any, mods ...func(r *http.Request)) *httptest.ResponseRecorder {
	var b []byte
	switch v := body.(type) {
	case string:
		b = []byte(v)
	case []byte:
		b = v
	default:
		b, _ = json.Marshal(v)
	}
	r := httptest.NewRequest(http.MethodPost, VerifyURL, bytes.NewReader(b))
	r.RemoteAddr = fxIP + ":5555"
	r.Header.Set("User-Agent", fxUA)
	r.Header.Set("Content-Type", "application/json")
	for _, m := range mods {
		m(r)
	}
	return e.do(r)
}

// passCookie returns the pass cookie set by a response, or nil.
func (e *fxEnv) passCookie(w *httptest.ResponseRecorder) *http.Cookie {
	for _, c := range w.Result().Cookies() {
		if c.Name == e.cookieName() && c.Value != "" && c.MaxAge >= 0 {
			return c
		}
	}
	return nil
}

func (e *fxEnv) totals() stats.Counters { return e.st.Snapshot("").Totals }

// fxCheck fails the test with the given message when failed is true. These
// assertions guard regressions of bugs these tests once found.
func fxCheck(t *testing.T, failed bool, format string, args ...any) {
	t.Helper()
	if failed {
		t.Errorf(format, args...)
	}
}
