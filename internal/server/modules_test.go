package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tamamo/tamamo/internal/config"
)

func setModules(t *testing.T, s *Server, mods ...config.ModuleConfig) {
	t.Helper()
	if err := s.mgr.Update(func(c *config.Config) error {
		c.Modules = mods
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// ruleCount returns how many requests stats attributed to rule name.
func ruleCount(s *Server, name string) int64 {
	for _, n := range s.st.Snapshot("").TopRules {
		if n.Name == name {
			return n.Count
		}
	}
	return 0
}

func TestModulesRunBeforeRules(t *testing.T) {
	s, _, seen := setup(t)
	var calls atomic.Int32
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		switch body["path"] {
		case "/robots.txt":
			io.WriteString(w, `{"action":"block","reason":"webhook says no"}`)
		case "/hard":
			io.WriteString(w, `{"action":"challenge","difficulty":3}`)
		default:
			io.WriteString(w, `{}`)
		}
	}))
	defer hook.Close()
	const secret = "monitor-secret-0123456789"
	setModules(t, s,
		config.ModuleConfig{Name: "monitors", Type: "go", Module: "bypass-header", Enabled: true,
			Settings: map[string]string{"header": "X-Monitor", "value": secret}},
		config.ModuleConfig{Name: "hook", Type: "webhook", URL: hook.URL, Enabled: true},
		config.ModuleConfig{Name: "off", Type: "webhook", URL: "http://127.0.0.1:1/", Enabled: false, OnError: "block"},
	)

	// robots.txt is allowed by a default rule, but the webhook runs first.
	if w := get(s, "/robots.txt", "curl/8"); w.Code != 403 {
		t.Fatalf("webhook block: %d", w.Code)
	}
	if n := ruleCount(s, "module:hook"); n != 1 {
		t.Errorf("module:hook counted %d times", n)
	}
	// The first module with an opinion wins: the bypass header beats the webhook.
	r := httptest.NewRequest("GET", "/robots.txt", nil)
	r.RemoteAddr = "192.0.2.10:5555"
	r.Header.Set("X-Monitor", secret)
	w := httptest.NewRecorder()
	before := calls.Load()
	s.ServeHTTP(w, r)
	if w.Code != 200 || seen.path != "/robots.txt" {
		t.Fatalf("bypass: %d", w.Code)
	}
	if calls.Load() != before {
		t.Error("webhook asked after an earlier module decided")
	}
	if n := ruleCount(s, "module:monitors"); n != 1 {
		t.Errorf("module:monitors counted %d times", n)
	}
	// Module difficulty is used for the challenge.
	w = get(s, "/hard", browserUA)
	if _, c := extractChallenge(t, w.Body.String()); c.D != 3 {
		t.Errorf("difficulty %d", c.D)
	}
	// No opinion: the rules decide (the default rules allow the favicon).
	if w := get(s, "/favicon.ico", "curl/8"); w.Code != 200 {
		t.Errorf("rules after no opinion: %d", w.Code)
	}
	if n := ruleCount(s, "module:hook"); n != 2 { // 1 block + 1 challenge (/hard)
		t.Errorf("module:hook counted %d times", n)
	}
	// nginx auth_request mode uses the modules too.
	if w := authReq(s, "/robots.txt", "curl/8", nil); w.Code != 403 {
		t.Errorf("auth mode: %d", w.Code)
	}
	if w := authReq(s, "/robots.txt", "curl/8", map[string]string{"X-Monitor": secret}); w.Code != 204 {
		t.Errorf("auth mode bypass: %d", w.Code)
	}
}

func TestModuleOnError(t *testing.T) {
	s, _, _ := setup(t)
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		io.WriteString(w, `{"action":"allow"}`)
	}))
	defer slow.Close()
	broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down", 502)
	}))
	defer broken.Close()

	for _, tc := range []struct {
		url, onError string
		want         int
	}{
		{slow.URL, "", 200},            // continue (default): the robots.txt rule allows
		{slow.URL, "block", 403},       // timeout
		{broken.URL, "block", 403},     // non-2xx
		{broken.URL, "challenge", 200}, // challenge page
		{broken.URL, "continue", 200},
	} {
		setModules(t, s, config.ModuleConfig{Name: "w", Type: "webhook", URL: tc.url, TimeoutMs: 50, OnError: tc.onError, Enabled: true})
		w := get(s, "/robots.txt", browserUA)
		if w.Code != tc.want {
			t.Errorf("%s on_error=%q: %d, want %d", tc.url, tc.onError, w.Code, tc.want)
		}
		if tc.onError == "challenge" && !strings.Contains(w.Body.String(), `data-state="checking"`) {
			t.Error("on_error=challenge did not show the checking page")
		}
	}
}

func TestRateLimitModule(t *testing.T) {
	s, _, _ := setup(t)
	setModules(t, s, config.ModuleConfig{Name: "ratelimit", Type: "go", Enabled: true,
		Settings: map[string]string{"requests": "2", "window_seconds": "60"}})
	for i, want := range []int{200, 200, 403, 403} {
		if w := get(s, "/robots.txt", "curl/8"); w.Code != want {
			t.Errorf("request %d: %d, want %d", i, w.Code, want)
		}
	}
	// Unrelated config changes keep the counters.
	if err := s.mgr.Update(func(c *config.Config) error { c.Protection.Difficulty = 2; return nil }); err != nil {
		t.Fatal(err)
	}
	if w := get(s, "/robots.txt", "curl/8"); w.Code != 403 {
		t.Errorf("counter reset by config update: %d", w.Code)
	}
}

func TestModuleSites(t *testing.T) {
	s, _, _ := setup(t)
	if err := s.mgr.Update(func(c *config.Config) error {
		c.Sites = []config.Site{{ID: "blog", Name: "Blog", Hosts: []string{"blog.example"}}}
		c.Modules = []config.ModuleConfig{{Name: "ratelimit", Type: "go", Enabled: true, Sites: []string{"blog"},
			Settings: map[string]string{"requests": "1"}}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if w := get(s, "/robots.txt", "curl/8"); w.Code != 200 {
			t.Fatalf("default site limited: %d", w.Code)
		}
	}
	hit := func() int {
		r := httptest.NewRequest("GET", "http://blog.example/robots.txt", nil)
		r.RemoteAddr = "192.0.2.10:5555"
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		return w.Code
	}
	if c := hit(); c != 200 {
		t.Errorf("first blog request: %d", c)
	}
	if c := hit(); c != 403 {
		t.Errorf("second blog request: %d", c)
	}
}

func TestPageModules(t *testing.T) {
	s, _, _ := setup(t)
	dir := t.TempDir()
	s.SetDataDir(dir)
	mod := filepath.Join(dir, "modules", "banner")
	for name, body := range map[string]string{
		"head.html":     `<meta name="banner-head" content="{module}">`,
		"body.html":     `<div class="banner"><img src="{module}/logo.png">unclosed <b>bold`,
		"style.css":     `.banner{color:red}`,
		"script.js":     `console.log(1)`,
		"logo.png":      "\x89PNG",
		".env":          "SECRET=1",
		"sub/notes.txt": "hi",
	} {
		p := filepath.Join(mod, name)
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	_ = os.WriteFile(filepath.Join(dir, "modules", "outside.txt"), []byte("no"), 0o644)
	_ = os.MkdirAll(filepath.Join(dir, "modules", "other"), 0o755)
	_ = os.WriteFile(filepath.Join(dir, "modules", "other", "style.css"), []byte("x"), 0o644)
	setModules(t, s, config.ModuleConfig{Name: "banner", Type: "page", Enabled: true})

	body := get(s, "/", browserUA).Body.String()
	for _, want := range []string{
		`<meta name="banner-head" content="/.tamamo/modules/banner">`,
		`<link rel="stylesheet" href="/.tamamo/modules/banner/style.css?v=`,
		`<script src="/.tamamo/modules/banner/script.js?v=`,
		`<div class="tm-module" data-module="banner"><div class="banner"><img src="/.tamamo/modules/banner/logo.png">unclosed <b>bold</b></div></div>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %s", want)
		}
	}
	head, _, _ := strings.Cut(body, "</head>")
	if !strings.Contains(head, "banner-head") || strings.Index(head, "banner-head") > strings.Index(head, "html body>footer.tm-credit") {
		t.Error("head.html must be in <head>, before the credit guard")
	}
	// The credit line stays the last element of <body>.
	if i, j := strings.Index(body, `class="banner"`), strings.Index(body, `<footer class="tm-credit"`); i < 0 || j < i {
		t.Error("body.html must come before the credit line")
	}
	if !strings.HasSuffix(strings.TrimSpace(body), "</footer>\n</body>\n</html>") {
		t.Errorf("credit line is not last:\n%s", body[len(body)-200:])
	}

	fetch := func(path string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "/x", nil)
		r.URL.Path = path
		r.RemoteAddr = "192.0.2.10:5555"
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		return w
	}
	if w := fetch("/.tamamo/modules/banner/style.css"); w.Code != 200 || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/css") {
		t.Errorf("style.css: %d %s", w.Code, w.Header().Get("Content-Type"))
	}
	if w := fetch("/.tamamo/modules/banner/script.js"); w.Code != 200 || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/javascript") {
		t.Errorf("script.js: %d %s", w.Code, w.Header().Get("Content-Type"))
	}
	if w := fetch("/.tamamo/modules/banner/sub/notes.txt"); w.Code != 200 || w.Body.String() != "hi" {
		t.Errorf("sub/notes.txt: %d", w.Code)
	}
	for _, p := range []string{
		"/.tamamo/modules/banner/head.html", "/.tamamo/modules/banner/body.html", "/.tamamo/modules/banner/.env",
		"/.tamamo/modules/banner/../outside.txt", "/.tamamo/modules/banner/sub/../../outside.txt",
		"/.tamamo/modules/../modules/outside.txt", "/.tamamo/modules/banner/", "/.tamamo/modules/banner",
		"/.tamamo/modules/other/style.css", // folder exists but the module isn't configured
		"/.tamamo/modules/banner/%2e%2e/outside.txt",
	} {
		if w := fetch(p); w.Code != 404 {
			t.Errorf("%s: %d, want 404", p, w.Code)
		}
	}
	if w := fetch("/.tamamo/modules/banner/style.css"); w.Code != 200 {
		t.Fatal("sanity")
	}
	r := httptest.NewRequest("POST", "/.tamamo/modules/banner/style.css", nil)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != 405 {
		t.Errorf("POST: %d", w.Code)
	}

	// Switched off: neither injected nor served.
	setModules(t, s, config.ModuleConfig{Name: "banner", Type: "page", Enabled: false})
	if strings.Contains(get(s, "/", browserUA).Body.String(), "banner") {
		t.Error("disabled module injected")
	}
	if w := fetch("/.tamamo/modules/banner/style.css"); w.Code != 404 {
		t.Errorf("disabled module served: %d", w.Code)
	}
	// A configured module without a folder is skipped quietly.
	setModules(t, s, config.ModuleConfig{Name: "ghost", Type: "page", Enabled: true})
	if w := get(s, "/", browserUA); w.Code != 200 || strings.Contains(w.Body.String(), `class="tm-module"`) {
		t.Errorf("missing folder: %d", w.Code)
	}
}

func TestPageLanguage(t *testing.T) {
	s, _, _ := setup(t)
	page := func(al string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = "192.0.2.10:5555"
		r.Header.Set("User-Agent", browserUA)
		r.Header.Set("Sec-Fetch-Mode", "navigate")
		if al != "" {
			r.Header.Set("Accept-Language", al)
		}
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		return w
	}
	ru := config.DefaultTranslations()["ru"].Texts.Checking.Heading
	uk := config.DefaultTranslations()["uk"].Texts.Checking.Heading
	for _, tc := range []struct{ al, lang, heading string }{
		{"ru-RU,ru;q=0.9,en;q=0.8", "ru", ru},
		{"uk", "uk", uk},
		{"en-US,en;q=0.9,ru;q=0.8", "en", ""},
		{"de-DE, fr;q=0.8", "en", ""},
		{"ru;q=0.5, uk;q=0.9", "uk", uk},
		{"", "en", ""},
	} {
		w := page(tc.al)
		b := w.Body.String()
		if !strings.Contains(b, `<html lang="`+tc.lang+`">`) {
			t.Errorf("%q: wrong lang", tc.al)
		}
		if tc.heading != "" && !strings.Contains(b, tc.heading) {
			t.Errorf("%q: heading %q missing", tc.al, tc.heading)
		}
		if !strings.Contains(strings.Join(w.Header().Values("Vary"), ","), "Accept-Language") {
			t.Errorf("%q: no Vary: Accept-Language", tc.al)
		}
	}
	// Switched off (language set to the main one): always the main texts.
	if err := s.mgr.Update(func(c *config.Config) error { c.Page.Language = "en"; return nil }); err != nil {
		t.Fatal(err)
	}
	if b := page("ru").Body.String(); !strings.Contains(b, `<html lang="en">`) {
		t.Error("auto_language off still translated")
	}

	// Forced language: Russian regardless of Accept-Language.
	if err := s.mgr.Update(func(c *config.Config) error { c.Page.Language = "ru"; return nil }); err != nil {
		t.Fatal(err)
	}
	for _, al := range []string{"", "en-US,en;q=0.9", "uk", "de-DE, fr;q=0.8"} {
		w := page(al)
		if b := w.Body.String(); !strings.Contains(b, `<html lang="ru">`) || !strings.Contains(b, ru) {
			t.Errorf("forced ru, Accept-Language %q: Russian page expected", al)
		}
	}
}

func TestTranslatedServerMessages(t *testing.T) {
	s, _, _ := setup(t)
	ru := config.DefaultTranslations()["ru"].Labels
	b, _ := json.Marshal(map[string]any{"token": "garbage", "nonce": "1"})
	r := httptest.NewRequest("POST", VerifyURL, strings.NewReader(string(b)))
	r.RemoteAddr = "192.0.2.10:5555"
	r.Header.Set("Accept-Language", "ru-RU,ru;q=0.9")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if w.Code != 403 || out["error"] != ru.ChallengeInvalid {
		t.Errorf("verify error %d %v", w.Code, out["error"])
	}
	if w := postVerify(s, map[string]any{"token": "garbage"}); !strings.Contains(w.Body.String(), config.DefaultLabels().ChallengeInvalid) {
		t.Errorf("english verify error: %s", w.Body.String())
	}

	if err := s.mgr.Update(func(c *config.Config) error { c.Server.Target = ""; return nil }); err != nil {
		t.Fatal(err)
	}
	r = httptest.NewRequest("GET", "/robots.txt", nil)
	r.Header.Set("Accept-Language", "uk")
	w = httptest.NewRecorder()
	s.ServeHTTP(w, r)
	uk := config.DefaultTranslations()["uk"].Labels
	if w.Code != 502 || !strings.Contains(w.Body.String(), uk.UpstreamMissing) {
		t.Errorf("upstream missing page: %d", w.Code)
	}
	if b := get(s, "/robots.txt", "curl/8").Body.String(); !strings.Contains(b, config.DefaultLabels().UpstreamMissing) {
		t.Error("english upstream message missing")
	}
}
