package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/foxgirlsorg/tamamo/internal/assets"
	"github.com/foxgirlsorg/tamamo/internal/config"
)

func init() { pbkdf2Iterations = 1000 }

type env struct {
	t   *testing.T
	h   http.Handler
	cfg *config.Manager
}

func newEnv(t *testing.T) *env {
	t.Helper()
	dir := t.TempDir()
	cfg, err := config.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	st, err := assets.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	return &env{t: t, cfg: cfg, h: New(Options{Config: cfg, Assets: st, Version: "test"})}
}

type resp struct {
	code   int
	body   map[string]any
	raw    string
	cookie *http.Cookie
}

func (e *env) do(method, path, body string, cookie *http.Cookie, csrf bool) resp {
	e.t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.RemoteAddr = "192.0.2.10:5555"
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if csrf {
		req.Header.Set(csrfHeader, "1")
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	out := resp{code: rec.Code, raw: rec.Body.String()}
	_ = json.Unmarshal(rec.Body.Bytes(), &out.body)
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookie && c.Value != "" {
			out.cookie = c
		}
	}
	return out
}

func (e *env) setup() *http.Cookie {
	e.t.Helper()
	r := e.do("POST", "/api/setup", `{"username":"admin","password":"correct horse battery"}`, nil, true)
	if r.code != 200 || r.cookie == nil {
		e.t.Fatalf("setup: %d %s", r.code, r.raw)
	}
	return r.cookie
}

func TestSetupFlow(t *testing.T) {
	e := newEnv(t)
	st := e.do("GET", "/api/state", "", nil, false)
	if st.body["setup_required"] != true || st.body["authenticated"] != false {
		t.Fatalf("unexpected state %v", st.body)
	}
	if r := e.do("POST", "/api/setup", `{"username":"admin","password":"short"}`, nil, true); r.code != 400 {
		t.Fatalf("short password accepted: %d", r.code)
	}
	c := e.setup()
	if !c.HttpOnly || c.SameSite != http.SameSiteStrictMode {
		t.Fatalf("cookie flags wrong: %+v", c)
	}
	stored := e.cfg.Stored()
	if !strings.HasPrefix(stored.Admin.PasswordHash, "pbkdf2-sha256$1000$") || stored.Admin.Username != "admin" {
		t.Fatalf("bad stored login %q %q", stored.Admin.Username, stored.Admin.PasswordHash)
	}
	st = e.do("GET", "/api/state", "", c, false)
	if st.body["setup_required"] != false || st.body["authenticated"] != true || st.body["username"] != "admin" {
		t.Fatalf("unexpected state after setup %v", st.body)
	}
	// Second setup is refused.
	r := e.do("POST", "/api/setup", `{"username":"evil","password":"another long password"}`, nil, true)
	if r.code != http.StatusConflict {
		t.Fatalf("second setup: %d %s", r.code, r.raw)
	}
	if e.cfg.Stored().Admin.Username != "admin" {
		t.Fatal("second setup changed the username")
	}
	// Login works with the right password.
	r = e.do("POST", "/api/login", `{"username":"admin","password":"correct horse battery"}`, nil, true)
	if r.code != 200 || r.cookie == nil {
		t.Fatalf("login: %d %s", r.code, r.raw)
	}
	// Logout invalidates the session.
	e.do("POST", "/api/logout", "", r.cookie, true)
	if g := e.do("GET", "/api/config", "", r.cookie, false); g.code != 401 {
		t.Fatalf("session survived logout: %d", g.code)
	}
}

func TestLoginLockout(t *testing.T) {
	e := newEnv(t)
	e.setup()
	now := time.Now()
	e.h.(*handler).limiter.now = func() time.Time { return now }
	for i := 0; i < freeFailures; i++ {
		r := e.do("POST", "/api/login", `{"username":"admin","password":"wrong password!"}`, nil, true)
		if r.code != 401 {
			t.Fatalf("attempt %d: %d", i, r.code)
		}
	}
	// Even the right password is refused while locked out.
	r := e.do("POST", "/api/login", `{"username":"admin","password":"correct horse battery"}`, nil, true)
	if r.code != http.StatusTooManyRequests {
		t.Fatalf("expected lockout, got %d %s", r.code, r.raw)
	}
	// Wrong user and wrong password give the same message.
	now = now.Add(firstLockout + time.Second)
	a := e.do("POST", "/api/login", `{"username":"nobody","password":"correct horse battery"}`, nil, true)
	if a.code != 401 {
		t.Fatalf("expected 401, got %d", a.code)
	}
	// The second lockout is longer (doubled).
	r = e.do("POST", "/api/login", `{"username":"admin","password":"correct horse battery"}`, nil, true)
	if r.code != http.StatusTooManyRequests {
		t.Fatalf("expected second lockout, got %d", r.code)
	}
	now = now.Add(firstLockout + time.Second)
	if r = e.do("POST", "/api/login", `{"username":"admin","password":"correct horse battery"}`, nil, true); r.code != http.StatusTooManyRequests {
		t.Fatalf("lockout did not double: %d", r.code)
	}
	now = now.Add(firstLockout * 2)
	if r = e.do("POST", "/api/login", `{"username":"admin","password":"correct horse battery"}`, nil, true); r.code != 200 {
		t.Fatalf("login after lockout: %d %s", r.code, r.raw)
	}
}

func TestCSRFHeaderRequired(t *testing.T) {
	e := newEnv(t)
	if r := e.do("POST", "/api/setup", `{"username":"admin","password":"correct horse battery"}`, nil, false); r.code != 403 {
		t.Fatalf("setup without header: %d", r.code)
	}
	c := e.setup()
	if r := e.do("POST", "/api/secret/rotate", "", c, false); r.code != 403 {
		t.Fatalf("rotate without header: %d", r.code)
	}
	if r := e.do("PUT", "/api/config", `{}`, c, false); r.code != 403 {
		t.Fatalf("put without header: %d", r.code)
	}
	if r := e.do("POST", "/api/logout", "", c, false); r.code != 403 {
		t.Fatalf("logout without header: %d", r.code)
	}
	// Reads don't need it, but do need a session.
	if r := e.do("GET", "/api/config", "", c, false); r.code != 200 {
		t.Fatalf("get config: %d", r.code)
	}
	if r := e.do("GET", "/api/config", "", nil, false); r.code != 401 {
		t.Fatalf("get config without session: %d", r.code)
	}
}

func TestConfigPutKeepsSecrets(t *testing.T) {
	e := newEnv(t)
	c := e.setup()
	before := e.cfg.Stored()

	g := e.do("GET", "/api/config", "", c, false)
	if strings.Contains(g.raw, before.Secret) || strings.Contains(g.raw, before.Admin.PasswordHash) {
		t.Fatal("GET /api/config leaks the secret or password hash")
	}
	cfgMap := g.body["config"].(map[string]any)
	cfgMap["secret"] = "attacker-secret"
	adm := cfgMap["admin"].(map[string]any)
	adm["password_hash"] = "pbkdf2-sha256$1$00$00"
	adm["username"] = "mallory"
	cfgMap["protection"].(map[string]any)["difficulty"] = 6
	body, _ := json.Marshal(cfgMap)

	r := e.do("PUT", "/api/config", string(body), c, true)
	if r.code != 200 {
		t.Fatalf("put: %d %s", r.code, r.raw)
	}
	after := e.cfg.Stored()
	if after.Secret != before.Secret || after.Admin.PasswordHash != before.Admin.PasswordHash || after.Admin.Username != "admin" {
		t.Fatal("PUT /api/config changed protected fields")
	}
	if after.Protection.Difficulty != 6 {
		t.Fatalf("difficulty not saved: %d", after.Protection.Difficulty)
	}

	// Validation errors come back as 400 with a message.
	cfgMap["page"].(map[string]any)["custom_css"] = ".tm-credit{display:none}"
	body, _ = json.Marshal(cfgMap)
	r = e.do("PUT", "/api/config", string(body), c, true)
	if r.code != 400 || r.body["error"] == nil {
		t.Fatalf("expected validation error, got %d %s", r.code, r.raw)
	}
}

func TestRuleTester(t *testing.T) {
	e := newEnv(t)
	c := e.setup()
	r := e.do("POST", "/api/test", `{"path":"/robots.txt","user_agent":"Mozilla/5.0 Chrome/130"}`, c, true)
	if rule, _ := r.body["rule"].(map[string]any); rule == nil || rule["id"] != "allow-robots-txt-and-well-known-files" || r.body["action"] != "allow" {
		t.Fatalf("robots.txt should be allowed: %v", r.body)
	}
	if site, _ := r.body["site"].(map[string]any); site == nil || site["id"] != config.DefaultSiteID {
		t.Fatalf("expected the default site: %v", r.body)
	}
	r = e.do("POST", "/api/test", `{"path":"/","user_agent":"Mozilla/5.0 (compatible; Googlebot/2.1)"}`, c, true)
	if rule, _ := r.body["rule"].(map[string]any); rule == nil || rule["id"] != "allow-search-engines" {
		t.Fatalf("Googlebot should be allowed as a search engine: %v", r.body)
	}
	r = e.do("POST", "/api/test", `{"path":"/","user_agent":"Mozilla/5.0 Chrome/130"}`, c, true)
	if r.body["action"] != "challenge" || r.body["difficulty"].(float64) != 4 {
		t.Fatalf("browser should be challenged at difficulty 4: %v", r.body)
	}
	if r = e.do("POST", "/api/test", `{"ip":"not-an-ip"}`, c, true); r.code != 400 {
		t.Fatalf("bad ip accepted: %d", r.code)
	}

	// A site with its own rules is resolved by host.
	if err := e.cfg.Update(func(cf *config.Config) error {
		cf.Sites = []config.Site{{ID: "blog", Name: "Blog", Hosts: []string{"blog.example.com"}, OwnRules: true,
			Rules: []config.Rule{{ID: "nope", Name: "Block all", Enabled: true, Action: config.ActionBlock}}}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	r = e.do("POST", "/api/test", `{"host":"blog.example.com:443","path":"/","user_agent":"Mozilla/5.0 Chrome/130"}`, c, true)
	site, _ := r.body["site"].(map[string]any)
	if site == nil || site["id"] != "blog" || r.body["action"] != "block" {
		t.Fatalf("blog site rules not used: %v", r.body)
	}
	r = e.do("POST", "/api/test", `{"host":"other.example.com","path":"/","user_agent":"Mozilla/5.0 Chrome/130"}`, c, true)
	if r.body["action"] != "challenge" {
		t.Fatalf("other hosts should use the global rules: %v", r.body)
	}
}

func TestConfigPresets(t *testing.T) {
	e := newEnv(t)
	c := e.setup()
	r := e.do("GET", "/api/config", "", c, false)
	d, _ := r.body["defaults"].(map[string]any)
	if p, _ := d["presets"].([]any); len(p) < 8 {
		t.Fatalf("expected rule presets, got %v", d["presets"])
	}
}

func TestSecurityHeadersAndNoUI(t *testing.T) {
	e := newEnv(t)
	req := httptest.NewRequest("GET", "/api/state", nil)
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Fatalf("missing CSP: %q", csp)
	}
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("missing nosniff")
	}

	// Only the API and the preview's static files are served. Nothing else,
	// in particular no HTML pages, comes back as a 200.
	// A path with ".." is cleaned by the mux (redirect), so it only has to
	// not be served.
	traversal := httptest.NewRecorder()
	e.h.ServeHTTP(traversal, httptest.NewRequest("GET", "/assets/../admin/index.html", nil))
	if traversal.Code == http.StatusOK {
		t.Fatal("/assets/../admin/index.html was served")
	}
	for _, p := range []string{"/assets/.keep", "/assets/challenge/page.html", "/assets/challenge/.x", "/rules", "/setup", "/index.html", "/assets/admin/app.js"} {
		rec := httptest.NewRecorder()
		e.h.ServeHTTP(rec, httptest.NewRequest("GET", p, nil))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("%s: got %d, want 404", p, rec.Code)
		}
		if !strings.HasPrefix(rec.Header().Get("Content-Type"), "application/json") {
			t.Fatalf("%s: 404 is not JSON (%q)", p, rec.Header().Get("Content-Type"))
		}
	}
	for _, p := range []string{"/api/i18n", "/api/i18n/en"} {
		if r := e.do("GET", p, "", nil, false); r.code != http.StatusNotFound {
			t.Fatalf("%s: got %d, want 404 (the i18n API is gone)", p, r.code)
		}
	}

	// Static files the preview needs are still served.
	for _, p := range []string{"/assets/mascot/checking.png", "/assets/challenge/worker.js", "/assets/challenge/solver.js"} {
		rec := httptest.NewRecorder()
		e.h.ServeHTTP(rec, httptest.NewRequest("GET", p, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: got %d, want 200", p, rec.Code)
		}
	}
}

func TestRootIdentifiesAdminAPI(t *testing.T) {
	e := newEnv(t)
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || rec.Code != http.StatusOK {
		t.Fatalf("GET /: %d %s", rec.Code, rec.Body.String())
	}
	if body["name"] != "tamamo" || body["admin_api"] != true || body["version"] != "test" {
		t.Fatalf("GET /: %v", body)
	}
	if r := e.do("POST", "/", "", nil, true); r.code != http.StatusNotFound {
		t.Fatalf("POST /: got %d, want 404", r.code)
	}
	if r := e.do("GET", "/api/state", "", nil, false); r.code != 200 {
		t.Fatalf("state: %d", r.code)
	}
}

func TestPasswordHash(t *testing.T) {
	h, err := hashPassword("hello world 123")
	if err != nil {
		t.Fatal(err)
	}
	if !verifyPassword(h, "hello world 123") || verifyPassword(h, "hello world 124") {
		t.Fatal("verify mismatch")
	}
	if verifyPassword("garbage", "x") {
		t.Fatal("garbage hash verified")
	}
}

// Behind the web UI container every sign-in comes from one address. With
// that proxy trusted, the lockout follows the address it reports.
func TestLoginLockoutBehindTrustedProxy(t *testing.T) {
	login := func(e *env, forwarded, password string) int {
		req := httptest.NewRequest("POST", "/api/login", strings.NewReader(`{"username":"admin","password":"`+password+`"}`))
		req.RemoteAddr = "172.18.0.5:40000" // the web UI container
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(csrfHeader, "1")
		req.Header.Set("X-Forwarded-For", forwarded)
		rec := httptest.NewRecorder()
		e.h.ServeHTTP(rec, req)
		return rec.Code
	}
	const wrong, right = "wrong password!", "correct horse battery"

	e := newEnv(t)
	e.setup()
	if err := e.cfg.Update(func(c *config.Config) error { c.Admin.TrustedProxies = []string{"private"}; return nil }); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < freeFailures; i++ {
		login(e, "203.0.113.50", wrong)
	}
	if code := login(e, "203.0.113.50", right); code != http.StatusTooManyRequests {
		t.Errorf("the attacker is not locked out: %d", code)
	}
	if code := login(e, "198.51.100.7", right); code != 200 {
		t.Errorf("the admin is locked out by someone else's failures: %d", code)
	}
	// A made-up address in front of the real one doesn't help.
	if code := login(e, "1.2.3.4, 203.0.113.50", right); code != http.StatusTooManyRequests {
		t.Errorf("a spoofed X-Forwarded-For entry dodged the lockout: %d", code)
	}

	// Without trusted proxies the header is ignored, as before.
	e = newEnv(t)
	e.setup()
	for i := 0; i < freeFailures; i++ {
		login(e, "203.0.113.50", wrong)
	}
	if code := login(e, "198.51.100.7", right); code != http.StatusTooManyRequests {
		t.Errorf("X-Forwarded-For was believed without a trusted proxy: %d", code)
	}
	if err := e.cfg.Update(func(c *config.Config) error { c.Admin.TrustedProxies = []string{"not an address"}; return nil }); err == nil {
		t.Error("a bad trusted proxy was accepted")
	}
}
