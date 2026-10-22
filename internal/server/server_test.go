package server

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/tamamo/tamamo/internal/assets"
	"github.com/tamamo/tamamo/internal/config"
	"github.com/tamamo/tamamo/internal/core"
	"github.com/tamamo/tamamo/internal/stats"
)

const browserUA = "Mozilla/5.0 (X11; Linux x86_64) Test/1.0"

type upstreamSeen struct {
	cookie, realIP, host, path string
}

func setup(t *testing.T) (*Server, *stats.Stats, *upstreamSeen) {
	t.Helper()
	seen := &upstreamSeen{}
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.cookie = r.Header.Get("Cookie")
		seen.realIP = r.Header.Get("X-Real-IP")
		seen.host = r.Host
		seen.path = r.URL.RequestURI()
		_, _ = io.WriteString(w, "upstream says hi")
	}))
	t.Cleanup(up.Close)

	dir := t.TempDir()
	t.Setenv("TAMAMO_TARGET", "")
	mgr, err := config.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := mgr.Update(func(c *config.Config) error {
		c.Server.Target = up.URL
		c.Protection.Difficulty = 1
		c.Stats.Enabled = true
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
	return New(mgr, st, as), st, seen
}

func get(s *Server, path, ua string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", path, nil)
	r.RemoteAddr = "192.0.2.10:5555"
	r.Header.Set("User-Agent", ua)
	r.Header.Set("Sec-Fetch-Mode", "navigate")
	r.Header.Set("Sec-Fetch-Dest", "document")
	for _, c := range cookies {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

func mustAddr(s string) netip.Addr { return netip.MustParseAddr(s) }

var tokenRe = regexp.MustCompile(`[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{43}`)

// extractChallenge finds the signed challenge token in a rendered page and
// decodes its (unverified) claims.
func extractChallenge(t *testing.T, body string) (string, core.ChallengeClaims) {
	t.Helper()
	tok := tokenRe.FindString(body)
	if tok == "" {
		t.Fatalf("no token in page:\n%s", body)
	}
	payload, _, _ := strings.Cut(tok, ".")
	b, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		t.Fatal(err)
	}
	var c core.ChallengeClaims
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	return tok, c
}

func solve(t *testing.T, c core.ChallengeClaims) string {
	t.Helper()
	for n := 0; n < 50_000_000; n++ {
		if _, ok := core.CheckPoW(c.R, strconv.Itoa(n), c.D); ok {
			return strconv.Itoa(n)
		}
	}
	t.Fatal("no solution")
	return ""
}

func postVerify(s *Server, body any) *httptest.ResponseRecorder {
	b, _ := json.Marshal(body)
	r := httptest.NewRequest("POST", VerifyURL, strings.NewReader(string(b)))
	r.RemoteAddr = "192.0.2.10:5555"
	r.Header.Set("User-Agent", browserUA)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

func TestFullFlow(t *testing.T) {
	s, st, seen := setup(t)

	w := get(s, "/docs?page=2", browserUA)
	if w.Code != 200 || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("challenge: %d %s", w.Code, w.Header().Get("Content-Type"))
	}
	if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("X-Robots-Tag") == "" {
		t.Errorf("missing headers: %v", w.Header())
	}
	tok, claims := extractChallenge(t, w.Body.String())
	if claims.D != 1 {
		t.Fatalf("difficulty %d", claims.D)
	}
	nonce := solve(t, claims)

	// Wrong nonce first.
	bad := postVerify(s, map[string]any{"token": tok, "nonce": "x", "redirect": "/"})
	if bad.Code != 403 || !strings.Contains(bad.Body.String(), `"ok":false`) {
		t.Fatalf("bad nonce: %d %s", bad.Code, bad.Body)
	}

	v := postVerify(s, map[string]any{"token": tok, "nonce": nonce, "elapsed_ms": 1234, "redirect": "/docs?page=2"})
	if v.Code != 200 {
		t.Fatalf("verify: %d %s", v.Code, v.Body)
	}
	var vr struct {
		OK       bool   `json:"ok"`
		Redirect string `json:"redirect"`
	}
	_ = json.Unmarshal(v.Body.Bytes(), &vr)
	if !vr.OK || vr.Redirect != "/docs?page=2" {
		t.Fatalf("verify body %s", v.Body)
	}
	var pass *http.Cookie
	for _, c := range v.Result().Cookies() {
		if c.Name == "tamamo-pass" {
			pass = c
		}
	}
	if pass == nil || !pass.HttpOnly || pass.SameSite != http.SameSiteLaxMode || pass.Path != "/" || pass.MaxAge <= 0 {
		t.Fatalf("bad cookie %+v", pass)
	}

	// Replays are refused.
	if again := postVerify(s, map[string]any{"token": tok, "nonce": nonce}); again.Code != 403 {
		t.Errorf("replay accepted: %d", again.Code)
	}

	w = get(s, "/docs?page=2", browserUA, pass, &http.Cookie{Name: "app", Value: "1"})
	if w.Code != 200 || w.Body.String() != "upstream says hi" {
		t.Fatalf("proxied: %d %q", w.Code, w.Body)
	}
	if strings.Contains(seen.cookie, "tamamo-pass") || seen.cookie != "app=1" {
		t.Errorf("upstream cookie %q", seen.cookie)
	}
	if seen.realIP != "192.0.2.10" || seen.path != "/docs?page=2" || seen.host != "example.com" {
		t.Errorf("upstream saw %+v", seen)
	}

	// The pass is bound to the user agent.
	if w := get(s, "/", "Mozilla/5.0 Other", pass); w.Code != 200 || w.Body.String() == "upstream says hi" {
		t.Errorf("pass worked for another UA")
	}

	snap := st.Snapshot("")
	if snap.Totals.Solved != 1 || snap.Totals.Passed != 1 || snap.Totals.Failed != 2 || snap.Totals.Challenged != 2 {
		t.Errorf("stats %+v", snap.Totals)
	}
}

func TestBlockAndAllowRules(t *testing.T) {
	s, _, seen := setup(t)
	if err := s.mgr.Update(func(c *config.Config) error {
		c.Rules = append([]config.Rule{{Name: "no gpt", Enabled: true, Action: config.ActionBlock,
			Match: config.Match{UserAgents: []string{"*GPTBot*"}}}}, c.Rules...)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	w := get(s, "/", "Mozilla/5.0 (compatible; GPTBot/1.0)")
	if w.Code != 403 || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("block: %d", w.Code)
	}
	w = get(s, "/robots.txt", "Mozilla/5.0")
	if w.Code != 200 || w.Body.String() != "upstream says hi" || seen.path != "/robots.txt" {
		t.Fatalf("allow: %d %q", w.Code, w.Body)
	}
	w = get(s, "/x", "Mozilla/5.0 (compatible; Googlebot/2.1)")
	if w.Body.String() != "upstream says hi" {
		t.Fatalf("search engine: %d", w.Code)
	}
	// Everyone else is challenged by the default rules.
	w = get(s, "/x", "curl/8")
	if w.Code != 200 || w.Body.String() == "upstream says hi" {
		t.Fatalf("default challenge: %d", w.Code)
	}
}

func TestTamperedCookie(t *testing.T) {
	s, _, _ := setup(t)
	d := s.state()
	good := d.pass.Sign(core.PassClaims{D: 8, E: 1 << 40, I: 1, S: config.DefaultSiteID, B: core.BindHash(mustAddr("192.0.2.10"), browserUA, true, true)})
	if w := get(s, "/", browserUA, &http.Cookie{Name: "tamamo-pass", Value: good}); w.Body.String() != "upstream says hi" {
		t.Fatalf("valid forged-by-us pass rejected: %d", w.Code)
	}
	payload, sig, _ := strings.Cut(good, ".")
	bad := payload[:len(payload)-2] + "xx." + sig
	w := get(s, "/", browserUA, &http.Cookie{Name: "tamamo-pass", Value: bad})
	if w.Code != 200 || w.Body.String() == "upstream says hi" {
		t.Fatalf("tampered cookie passed")
	}
	// A challenge token presented as a pass is rejected too.
	chal := d.chal.Sign(core.PassClaims{D: 8, E: 1 << 40, S: config.DefaultSiteID, B: core.BindHash(mustAddr("192.0.2.10"), browserUA, true, true)})
	if w := get(s, "/", browserUA, &http.Cookie{Name: "tamamo-pass", Value: chal}); w.Body.String() == "upstream says hi" {
		t.Fatal("challenge-signed cookie passed")
	}
}

func TestNonNavigationGetsJSON(t *testing.T) {
	s, _, _ := setup(t)
	r := httptest.NewRequest("GET", "/api/data", nil)
	r.Header.Set("User-Agent", browserUA)
	r.Header.Set("Sec-Fetch-Mode", "cors")
	r.Header.Set("Sec-Fetch-Dest", "empty")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != 403 || !strings.Contains(w.Body.String(), "challenge_required") {
		t.Fatalf("got %d %s", w.Code, w.Body)
	}
}

func TestReservedEndpoints(t *testing.T) {
	s, _, _ := setup(t)
	if w := get(s, HealthURL, "x"); w.Code != 200 || w.Body.String() != "ok" {
		t.Errorf("health %d %q", w.Code, w.Body)
	}
	for _, p := range []string{"/.tamamo/static/index.html", "/.tamamo/static/.hidden", "/.tamamo/static/../embed.go", "/.tamamo/nope"} {
		if w := get(s, p, "x"); w.Code != 404 {
			t.Errorf("%s: %d", p, w.Code)
		}
	}
	if w := get(s, "/.tamamo/static/img/checking", "x"); w.Code != 200 || w.Header().Get("Content-Type") != "image/png" {
		t.Errorf("image: %d %s", w.Code, w.Header().Get("Content-Type"))
	}
	if w := get(s, VerifyURL, "x"); w.Code != 405 {
		t.Errorf("GET verify: %d", w.Code)
	}
}

func TestNoUpstream(t *testing.T) {
	s, _, _ := setup(t)
	if err := s.mgr.Update(func(c *config.Config) error { c.Server.Target = ""; return nil }); err != nil {
		t.Fatal(err)
	}
	if w := get(s, "/robots.txt", "curl"); w.Code != 502 {
		t.Fatalf("got %d", w.Code)
	}
}

func TestUpstreamDown(t *testing.T) {
	s, _, _ := setup(t)
	if err := s.mgr.Update(func(c *config.Config) error { c.Server.Target = "http://127.0.0.1:1"; return nil }); err != nil {
		t.Fatal(err)
	}
	if w := get(s, "/robots.txt", "curl"); w.Code != 502 || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("got %d", w.Code)
	}
}

func TestRateLimit(t *testing.T) {
	s, _, _ := setup(t)
	if err := s.mgr.Update(func(c *config.Config) error { c.Protection.MaxFailures = 2; return nil }); err != nil {
		t.Fatal(err)
	}
	codes := []int{}
	for i := 0; i < 3; i++ {
		codes = append(codes, postVerify(s, map[string]any{"token": "x.y", "nonce": "1"}).Code)
	}
	if codes[0] != 403 || codes[1] != 403 || codes[2] != 429 {
		t.Fatalf("codes %v", codes)
	}
}

func TestSafeRedirect(t *testing.T) {
	cases := map[string]string{
		"/a?b=c":           "/a?b=c",
		"":                 "/",
		"https://evil.com": "/",
		"//evil.com":       "/",
		"/\\evil.com":      "/",
		"/\t/evil.com":     "/",
		"/ok/\\x":          "/",
		"evil":             "/",
		"/%2F%2Fevil.com":  "/%2F%2Fevil.com",
		"/path#frag":       "/path#frag",
		"/\x00":            "/",
		"/café":            "/café",
	}
	for in, want := range cases {
		if got := safeRedirect(in); got != want {
			t.Errorf("safeRedirect(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestStripCookie(t *testing.T) {
	h := http.Header{}
	h.Add("Cookie", "a=1; tamamo-pass=xyz; b=2")
	h.Add("Cookie", "tamamo-pass=again")
	stripCookie(h, "tamamo-pass")
	if got := h.Values("Cookie"); len(got) != 1 || got[0] != "a=1; b=2" {
		t.Fatalf("got %q", got)
	}
	h = http.Header{"Cookie": {"tamamo-pass=1"}}
	stripCookie(h, "tamamo-pass")
	if _, ok := h["Cookie"]; ok {
		t.Fatal("empty cookie header kept")
	}
}

func TestSites(t *testing.T) {
	s, _, seen := setup(t)
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "other site")
	}))
	defer other.Close()
	if err := s.mgr.Update(func(c *config.Config) error {
		c.Sites = []config.Site{{
			Name: "Other", Hosts: []string{"*.other.test"}, Target: other.URL,
			OwnRules: true, Rules: []config.Rule{
				{Name: "block secret", Enabled: true, Action: config.ActionBlock, Match: config.Match{Paths: []string{"/secret"}}},
				{Name: "curl ok", Enabled: true, Action: config.ActionAllow, Match: config.Match{UserAgents: []string{"curl"}}},
			},
		}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	req := func(host, path string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", path, nil)
		r.Host = host
		r.Header.Set("User-Agent", "curl/8")
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		return w
	}
	if w := req("www.other.test:8923", "/"); w.Body.String() != "other site" {
		t.Errorf("site routing: %d %q", w.Code, w.Body)
	}
	if w := req("www.other.test", "/secret"); w.Code != 403 {
		t.Errorf("site rules: %d", w.Code)
	}
	if w := req("example.com", "/robots.txt"); w.Body.String() != "upstream says hi" || seen.path != "/robots.txt" {
		t.Errorf("default site: %d %q", w.Code, w.Body)
	}

	// A pass for the default site is useless on another site.
	ua := browserUA
	pass := s.state().pass.Sign(core.PassClaims{D: 8, E: 1 << 40, S: config.DefaultSiteID, B: core.BindHash(mustAddr("192.0.2.10"), ua, true, true)})
	r := httptest.NewRequest("GET", "/", nil)
	r.Host = "www.other.test"
	r.RemoteAddr = "192.0.2.10:1"
	r.Header.Set("User-Agent", ua)
	r.AddCookie(&http.Cookie{Name: "tamamo-pass", Value: pass})
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Body.String() == "other site" {
		t.Error("default-site pass accepted by another site")
	}
}

func TestHostOnly(t *testing.T) {
	if h := hostOnly("Shop.Example.COM:8923"); h != "shop.example.com" {
		t.Errorf("hostOnly: %q", h)
	}
	if h := hostOnly("[::1]:80"); h != "::1" {
		t.Errorf("hostOnly v6: %q", h)
	}
}

func authReq(s *Server, uri, ua string, hdr map[string]string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", AuthURL, nil)
	r.RemoteAddr = "192.0.2.10:5555"
	r.Header.Set("User-Agent", ua)
	r.Header.Set("X-Original-URI", uri)
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	for _, c := range cookies {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

func TestAuthRequest(t *testing.T) {
	s, st, _ := setup(t)
	if err := s.mgr.Update(func(c *config.Config) error {
		c.Rules = append([]config.Rule{{Name: "no posts", Enabled: true, Action: config.ActionBlock,
			Match: config.Match{Methods: []string{"POST"}, Paths: []string{"/admin*"}}}}, c.Rules...)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if w := authReq(s, "/robots.txt", "curl", nil); w.Code != 204 || w.Body.Len() != 0 {
		t.Errorf("allow: %d", w.Code)
	}
	if w := authReq(s, "/page?x=1", browserUA, nil); w.Code != 401 || w.Body.Len() != 0 {
		t.Errorf("challenge: %d", w.Code)
	}
	if w := authReq(s, "/admin/x", browserUA, map[string]string{"X-Original-Method": "POST"}); w.Code != 403 {
		t.Errorf("block: %d", w.Code)
	}
	pass := s.state().pass.Sign(core.PassClaims{D: 8, E: 1 << 40, S: config.DefaultSiteID, B: core.BindHash(mustAddr("192.0.2.10"), browserUA, true, true)})
	if w := authReq(s, "/page", browserUA, nil, &http.Cookie{Name: "tamamo-pass", Value: pass}); w.Code != 204 {
		t.Errorf("pass: %d", w.Code)
	}
	// X-Forwarded-Uri fallback.
	if w := authReq(s, "", "curl", map[string]string{"X-Forwarded-Uri": "/robots.txt"}); w.Code != 204 {
		t.Errorf("forwarded-uri: %d", w.Code)
	}
	tot := st.Snapshot("").Totals
	if tot.Allowed != 2 || tot.Passed != 1 || tot.Challenged != 0 || tot.Blocked != 0 {
		t.Errorf("stats %+v", tot)
	}
}

func renderReq(s *Server, uri, ua string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", uri, nil)
	r.RemoteAddr = "192.0.2.10:5555"
	r.Header.Set("User-Agent", ua)
	r.Header.Set(RenderHeader, "1")
	r.Header.Set("X-Original-URI", uri)
	for _, c := range cookies {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

func TestRenderOnly(t *testing.T) {
	s, st, seen := setup(t)
	seen.path = ""
	w := renderReq(s, "/docs?a=1", browserUA)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "/docs?a=1") {
		t.Fatalf("challenge: %d", w.Code)
	}
	tok, claims := extractChallenge(t, w.Body.String())
	nonce := solve(t, claims)
	v := postVerify(s, map[string]any{"token": tok, "nonce": nonce, "redirect": "/docs?a=1"})
	if v.Code != 200 {
		t.Fatalf("verify: %d %s", v.Code, v.Body)
	}
	pass := v.Result().Cookies()[0]

	// Allowed now: redirect back, never proxy.
	w = renderReq(s, "/docs?a=1", browserUA, pass)
	if w.Code != 302 || w.Header().Get("Location") != "/docs?a=1" || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("redirect: %d %v", w.Code, w.Header())
	}
	// Open redirects through X-Original-URI are neutralised.
	if w := renderReq(s, "//evil.example/", "Mozilla/5.0 (compatible; Googlebot/2.1)"); w.Code != 302 || w.Header().Get("Location") != "/" {
		t.Errorf("unsafe redirect: %d %s", w.Code, w.Header().Get("Location"))
	}
	if seen.path != "" {
		t.Errorf("render-only request was proxied: %q", seen.path)
	}
	if err := s.mgr.Update(func(c *config.Config) error {
		c.Rules = append([]config.Rule{{Name: "no gpt", Enabled: true, Action: config.ActionBlock,
			Match: config.Match{UserAgents: []string{"*GPTBot*"}}}}, c.Rules...)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if w := renderReq(s, "/", "GPTBot"); w.Code != 403 || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/html") {
		t.Errorf("denied: %d", w.Code)
	}
	tot := st.Snapshot("").Totals
	if tot.Challenged != 1 || tot.Blocked != 1 || tot.Solved != 1 || tot.Allowed != 0 || tot.Passed != 0 {
		t.Errorf("stats %+v", tot)
	}
}
