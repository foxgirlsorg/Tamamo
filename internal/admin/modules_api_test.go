package admin

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/foxgirlsorg/tamamo/internal/config"
	"github.com/foxgirlsorg/tamamo/internal/modules"
	"github.com/foxgirlsorg/tamamo/module"
)

type adminProbe struct{ ctx *module.Context }

func (p *adminProbe) ServeAdmin(w http.ResponseWriter, r *http.Request) {
	_, _ = io.WriteString(w, `{"path":"`+r.URL.Path+`","method":"`+r.Method+`","name":"`+p.ctx.Name+`"}`)
}

func (p *adminProbe) ExtendPage(pr *module.PageRequest) module.PageParts {
	preview := "live"
	if pr.Preview {
		preview = "preview"
	}
	return module.PageParts{Body: `<p id="ap">` + preview + `</p>`, Styles: []string{pr.AssetURL("a.css")}}
}

func init() {
	module.Register(module.Info{
		ID: "admin-probe", Name: "Admin probe", Description: "For tests.", Version: "1.2.3",
		Settings: []module.Field{{Name: "greeting", Default: "hi"}},
		Pages:    []module.Page{{ID: "main", Title: "Main"}},
		UI:       fstest.MapFS{"index.html": {Data: []byte("<h1>probe ui</h1>")}, "app.js": {Data: []byte("1")}},
		Static:   fstest.MapFS{"a.css": {Data: []byte(".a{}")}},
		New: func(ctx *module.Context) (module.Module, error) {
			return &adminProbe{ctx: ctx}, nil
		},
	})
}

// withModules gives the env a module host that follows the config.
func (e *env) withModules(t *testing.T, mods ...config.ModuleConfig) {
	t.Helper()
	host := modules.NewHost(t.TempDir())
	t.Cleanup(host.Close)
	e.cfg.Subscribe(func(c *config.Config) { host.Apply(c) })
	e.h.(*handler).o.Modules = host
	if err := e.cfg.Update(func(c *config.Config) error {
		c.Modules = mods
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func (e *env) raw(method, path string, cookie *http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	req.Header.Set(csrfHeader, "1")
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	return rec
}

func TestModulesAPI(t *testing.T) {
	e := newEnv(t)
	c := e.setup()
	e.withModules(t, config.ModuleConfig{Name: "first", Module: "admin-probe", Enabled: true},
		config.ModuleConfig{Name: "idle", Module: "admin-probe", Enabled: false})

	r := e.do("GET", "/api/modules", "", c, false)
	if r.code != 200 {
		t.Fatalf("modules: %d %s", r.code, r.raw)
	}
	for _, want := range []string{
		`"id":"admin-probe"`, `"name":"Admin probe"`, `"version":"1.2.3"`, `"has_ui":true`, `"has_static":true`,
		`"settings":[{"name":"greeting","label":"greeting"`, `"pages":[{"id":"main","title":"Main","path":"index.html"}]`,
		`"running":[{"name":"first","module":"admin-probe","hooks":["page","admin"],"error":""}]`,
	} {
		if !strings.Contains(r.raw, want) {
			t.Errorf("GET /api/modules lacks %s in %s", want, r.raw)
		}
	}
	if r := e.do("GET", "/api/modules", "", nil, false); r.code != 401 {
		t.Errorf("unauthenticated: %d", r.code)
	}

	// The module's own admin API.
	r = e.do("GET", "/api/x/first/stats/today", "", c, false)
	if r.code != 200 || r.body["path"] != "/stats/today" || r.body["name"] != "first" {
		t.Errorf("module API: %d %s", r.code, r.raw)
	}
	if r := e.do("POST", "/api/x/first/reset", "", c, true); r.code != 200 || r.body["method"] != "POST" {
		t.Errorf("module API POST: %d %s", r.code, r.raw)
	}
	if r := e.do("POST", "/api/x/first/reset", "", c, false); r.code != 403 {
		t.Errorf("POST without the CSRF header: %d", r.code)
	}
	if r := e.do("GET", "/api/x/first/stats", "", nil, false); r.code != 401 {
		t.Errorf("module API without a session: %d", r.code)
	}
	for _, name := range []string{"idle", "nobody"} {
		if r := e.do("GET", "/api/x/"+name+"/stats", "", c, false); r.code != 404 {
			t.Errorf("module %s is not running: %d", name, r.code)
		}
	}
}

func TestModuleFilesAndPreview(t *testing.T) {
	e := newEnv(t)
	c := e.setup()
	e.withModules(t, config.ModuleConfig{Name: "first", Module: "admin-probe", Enabled: true})

	// Web UI pages: signed-in only, framable by the web UI, no inline scripts.
	w := e.raw("GET", "/assets/modules/ui/admin-probe/index.html", c)
	if w.Code != 200 || w.Body.String() != "<h1>probe ui</h1>" {
		t.Fatalf("UI page: %d %q", w.Code, w.Body.String())
	}
	csp := w.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "frame-ancestors 'self'") || !strings.Contains(csp, "script-src 'self';") || strings.Contains(csp, "sandbox") {
		t.Errorf("UI page policy: %q", csp)
	}
	if w.Header().Get("X-Frame-Options") != "SAMEORIGIN" {
		t.Errorf("UI page must be framable by the web UI: %q", w.Header().Get("X-Frame-Options"))
	}
	for _, p := range []string{
		"/assets/modules/ui/admin-probe/missing.html", "/assets/modules/ui/nobody/index.html",
		"/assets/modules/ui/admin-probe/.hidden", "/assets/modules/static/admin-probe/index.html",
	} {
		if w := e.raw("GET", p, c); w.Code != 404 {
			t.Errorf("%s: %d", p, w.Code)
		}
	}
	for _, p := range []string{"/assets/modules/ui/admin-probe/index.html", "/assets/modules/static/admin-probe/a.css"} {
		if w := e.raw("GET", p, nil); w.Code != 404 {
			t.Errorf("%s without a session: %d", p, w.Code)
		}
	}
	if w := e.raw("GET", "/assets/modules/static/admin-probe/a.css", c); w.Code != 200 || w.Body.String() != ".a{}" {
		t.Errorf("static file: %d %q", w.Code, w.Body.String())
	}
	// The kit is plain static content.
	for _, f := range []string{"tamamo.js", "tamamo.css"} {
		if w := e.raw("GET", "/assets/modules/kit/"+f, nil); w.Code != 200 || w.Body.Len() < 500 {
			t.Errorf("kit %s: %d", f, w.Code)
		}
	}

	// The preview shows the module's parts with preview URLs.
	r := e.do("POST", "/api/preview", `{}`, c, true)
	if r.code != 200 || !strings.Contains(r.raw, `<p id="ap">preview</p>`) ||
		!strings.Contains(r.raw, `href="/assets/modules/static/admin-probe/a.css"`) {
		t.Errorf("preview: %d %s", r.code, r.raw)
	}
}
