package server

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/fstest"
	"time"

	"github.com/foxgirlsorg/tamamo/internal/config"
	"github.com/foxgirlsorg/tamamo/module"
)

// probe is a test module that implements every hook and records what it saw.
type probe struct {
	ctx *module.Context
}

var (
	probeMu      sync.Mutex
	probeEvents  []module.Event
	probeStarted atomic.Int32
	probeStopped atomic.Int32
)

func init() {
	module.Register(module.Info{
		ID: "probe",
		Settings: []module.Field{
			{Name: "block", Default: "/blocked"},
			{Name: "level", Type: module.Number, Default: "0", Min: 0, Max: 8},
		},
		Static: fstest.MapFS{
			"probe.css": {Data: []byte(".probe{}")},
			"page.html": {Data: []byte("<p>hi</p>")},
		},
		New: func(ctx *module.Context) (module.Module, error) {
			if ctx.Settings.String("block") == "invalid" {
				return nil, errors.New("block cannot be invalid")
			}
			return &probe{ctx: ctx}, nil
		},
	})
}

func (p *probe) Check(_ context.Context, r *module.Request) (module.Decision, error) {
	switch {
	case r.Path == p.ctx.Settings.String("block"):
		return module.Decision{Action: module.Block}, nil
	case r.Path == "/hard":
		return module.Decision{Action: module.Challenge, Difficulty: p.ctx.Settings.Int("level", 0)}, nil
	case r.Path == "/open":
		return module.Decision{Action: module.Allow}, nil
	case r.Path == "/boom":
		panic("boom")
	case r.Path == "/err":
		return module.Decision{}, errors.New("broken")
	}
	return module.Decision{}, nil
}

func (p *probe) Observe(e module.Event) {
	probeMu.Lock()
	probeEvents = append(probeEvents, e)
	probeMu.Unlock()
}

func (p *probe) ModifyRequest(out *http.Request, r *module.Request) {
	out.Header.Set("X-Probe-Site", r.Site)
}

func (p *probe) ModifyResponse(resp *http.Response, _ *module.Request) error {
	resp.Header.Set("X-Probe", p.ctx.Name)
	return nil
}

func (p *probe) ExtendPage(pr *module.PageRequest) module.PageParts {
	return module.PageParts{
		Head:   `<meta name="probe" content="` + pr.State + `">`,
		Body:   `<div id="probe-body"><b>unclosed`,
		Styles: []string{pr.AssetURL("probe.css")},
	}
}

func (p *probe) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/panic" {
		panic("handler boom")
	}
	_, _ = io.WriteString(w, "probe:"+r.Method+":"+r.URL.Path)
}

func (p *probe) Start(context.Context) error { probeStarted.Add(1); return nil }
func (p *probe) Stop() error                 { probeStopped.Add(1); return nil }

func setModules(t *testing.T, e *fxEnv, mods ...config.ModuleConfig) {
	t.Helper()
	if err := e.s.mgr.Update(func(c *config.Config) error {
		c.Modules = mods
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func ruleCount(e *fxEnv, name string) int64 {
	for _, n := range e.st.Snapshot("").TopRules {
		if n.Name == name {
			return n.Count
		}
	}
	return 0
}

func TestModuleChecksRunBeforeRules(t *testing.T) {
	e := fxNew(t, func(c *config.Config) {
		c.Rules = []config.Rule{fxRule("allow all", config.ActionAllow, config.Match{Paths: []string{"/*"}})}
		c.Modules = []config.ModuleConfig{{Name: "probe", Enabled: true}}
	})
	if w := e.get("/fine"); !e.proxied(w) {
		t.Fatalf("no opinion should fall through to the rules: %d", w.Code)
	}
	if w := e.get("/blocked"); w.Code != http.StatusForbidden {
		t.Fatalf("module block: %d", w.Code)
	}
	if n := ruleCount(e, "module:probe"); n != 1 {
		t.Errorf("module:probe counted %d times", n)
	}
	if w := e.get("/hard"); w.Code != http.StatusOK || e.proxied(w) {
		t.Fatalf("module challenge: %d", w.Code)
	}
	// A panic or an error is "no opinion" with on_error: continue.
	for _, p := range []string{"/boom", "/err"} {
		if w := e.get(p); !e.proxied(w) {
			t.Errorf("%s with on_error continue: %d", p, w.Code)
		}
	}
	setModules(t, e, config.ModuleConfig{Name: "probe", Enabled: true, OnError: "block"})
	for _, p := range []string{"/boom", "/err"} {
		if w := e.get(p); w.Code != http.StatusForbidden {
			t.Errorf("%s with on_error block: %d", p, w.Code)
		}
	}
	// Switched off: nothing runs.
	setModules(t, e, config.ModuleConfig{Name: "probe", Enabled: false})
	if w := e.get("/blocked"); !e.proxied(w) {
		t.Errorf("disabled module still decides: %d", w.Code)
	}
}

func TestModuleSettingsAndInstances(t *testing.T) {
	e := fxNew(t, func(c *config.Config) {
		c.Protection.DefaultAction = config.ActionAllow
		c.Modules = []config.ModuleConfig{
			{Name: "one", Module: "probe", Enabled: true, Settings: map[string]string{"block": "/a"}},
			{Name: "two", Module: "probe", Enabled: true, Settings: map[string]string{"block": "/b"}},
		}
	})
	for _, p := range []string{"/a", "/b"} {
		if w := e.get(p); w.Code != http.StatusForbidden {
			t.Errorf("%s: %d", p, w.Code)
		}
	}
	if w := e.get("/blocked"); !e.proxied(w) {
		t.Errorf("the default setting must not apply once it is set: %d", w.Code)
	}
	// Bad settings are refused when saving, and the old modules keep running.
	err := e.s.mgr.Update(func(c *config.Config) error {
		c.Modules[0].Settings["level"] = "99"
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "from 0 to 8") {
		t.Errorf("out-of-range number: %v", err)
	}
	err = e.s.mgr.Update(func(c *config.Config) error {
		c.Modules[0].Settings["block"] = "invalid"
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "cannot be invalid") {
		t.Errorf("error from New: %v", err)
	}
	err = e.s.mgr.Update(func(c *config.Config) error {
		c.Modules = append(c.Modules, config.ModuleConfig{Name: "ghost", Enabled: true})
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "compiled into this build") {
		t.Errorf("unknown module: %v", err)
	}
	if len(e.s.Modules().Instances()) != 2 {
		t.Errorf("instances: %d", len(e.s.Modules().Instances()))
	}
}

func TestModuleLifecycle(t *testing.T) {
	started, stopped := probeStarted.Load(), probeStopped.Load()
	e := fxNew(t, func(c *config.Config) {
		c.Modules = []config.ModuleConfig{{Name: "probe", Enabled: true}}
	})
	if probeStarted.Load() != started+1 {
		t.Fatalf("Start should run when the server is created")
	}
	in := e.s.Modules().Instance("probe")
	// An unrelated change keeps the instance.
	if err := e.s.mgr.Update(func(c *config.Config) error { c.Protection.Difficulty = 2; return nil }); err != nil {
		t.Fatal(err)
	}
	if e.s.Modules().Instance("probe") != in || probeStarted.Load() != started+1 {
		t.Errorf("an unrelated config change restarted the module")
	}
	// Changed settings replace it.
	setModules(t, e, config.ModuleConfig{Name: "probe", Enabled: true, Settings: map[string]string{"block": "/x"}})
	if e.s.Modules().Instance("probe") == in || probeStarted.Load() != started+2 || probeStopped.Load() != stopped+1 {
		t.Errorf("changed settings: started %d stopped %d", probeStarted.Load()-started, probeStopped.Load()-stopped)
	}
	e.s.Close()
	if probeStopped.Load() != stopped+2 {
		t.Errorf("Close should stop the running module")
	}
}

func TestModuleRoutesFilesAndPage(t *testing.T) {
	e := fxNew(t, func(c *config.Config) {
		c.Sites = []config.Site{{Name: "Shop", Hosts: []string{"shop.test"}}}
		c.Modules = []config.ModuleConfig{{Name: "probe", Enabled: true, Sites: []string{"Shop"}}}
	})
	shop := func(method, target string) *httptest.ResponseRecorder {
		r := fxReq(method, target)
		r.Host = "shop.test"
		return e.do(r)
	}
	// The module's own handler, any method, with the prefix cut off.
	if w := shop(http.MethodPost, ModuleRoutesURL+"/probe/hook/in?x=1"); w.Body.String() != "probe:POST:/hook/in" {
		t.Errorf("route: %d %q", w.Code, w.Body.String())
	}
	if w := shop(http.MethodGet, ModuleRoutesURL+"/probe/panic"); w.Code != http.StatusInternalServerError {
		t.Errorf("a panicking handler should answer 500, got %d", w.Code)
	}
	// Static files, locked down when they are documents.
	w := shop(http.MethodGet, ModulesURL+"/probe/probe.css")
	if w.Code != 200 || w.Body.String() != ".probe{}" || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/css") {
		t.Errorf("static file: %d %q %s", w.Code, w.Body.String(), w.Header().Get("Content-Type"))
	}
	if w := shop(http.MethodGet, ModulesURL+"/probe/page.html"); !strings.Contains(w.Header().Get("Content-Security-Policy"), "sandbox") {
		t.Errorf("HTML static files must be sandboxed")
	}
	for _, p := range []string{ModulesURL + "/probe/missing.css", ModulesURL + "/probe/../probe.css", ModulesURL + "/other/probe.css", ModuleRoutesURL + "/other/x"} {
		if w := shop(http.MethodGet, p); w.Code != http.StatusNotFound {
			t.Errorf("%s: %d", p, w.Code)
		}
	}
	// Other sites don't have the module.
	if w := e.get(ModuleRoutesURL + "/probe/x"); w.Code != http.StatusNotFound {
		t.Errorf("route on a site without the module: %d", w.Code)
	}
	if w := e.get(ModulesURL + "/probe/probe.css"); w.Code != http.StatusNotFound {
		t.Errorf("file on a site without the module: %d", w.Code)
	}
	// The checking page carries the module's parts; open elements are closed.
	page := shop(http.MethodGet, "/").Body.String()
	for _, want := range []string{
		`<meta name="probe" content="checking">`,
		`href="/.tamamo/modules/probe/probe.css"`,
		`<div id="probe-body"><b>unclosed</b></div>`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("checking page lacks %s", want)
		}
	}
	if strings.Contains(e.get("/").Body.String(), "probe-body") {
		t.Errorf("the page of a site without the module was extended")
	}
}

func TestModuleObserverAndProxyHooks(t *testing.T) {
	e := fxNew(t, func(c *config.Config) {
		c.Modules = []config.ModuleConfig{{Name: "probe", Enabled: true}}
	})
	probeMu.Lock()
	probeEvents = nil
	probeMu.Unlock()

	w := e.get("/open")
	if !e.proxied(w) {
		t.Fatalf("module allow: %d", w.Code)
	}
	if got := w.Header().Get("X-Probe"); got != "probe" {
		t.Errorf("ModifyResponse header: %q", got)
	}
	if got := e.up.last().header.Get("X-Probe-Site"); got != config.DefaultSiteID {
		t.Errorf("ModifyRequest header: %q", got)
	}
	e.get("/blocked")
	e.get("/")

	probeMu.Lock()
	defer probeMu.Unlock()
	var kinds []string
	for _, ev := range probeEvents {
		kinds = append(kinds, ev.Kind)
	}
	if strings.Join(kinds, ",") != "allow,block,challenge" {
		t.Fatalf("events: %v", kinds)
	}
	if ev := probeEvents[0]; ev.Path != "/open" || ev.Rule != "module:probe" || ev.IP != fxIP || ev.UserAgent != fxUA {
		t.Errorf("event: %+v", ev)
	}
}

// ---- built-in checks: bypass headers, rate limit, webhooks --------------------

func TestBypassHeaderRateLimitAndWebhookOrder(t *testing.T) {
	var calls atomic.Int32
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		b, _ := io.ReadAll(r.Body)
		switch {
		case strings.Contains(string(b), `"path":"/robots.txt"`):
			_, _ = io.WriteString(w, `{"action":"block","reason":"no"}`)
		case strings.Contains(string(b), `"path":"/down"`):
			w.WriteHeader(http.StatusInternalServerError)
		default:
			_, _ = io.WriteString(w, `{}`)
		}
	}))
	defer hook.Close()
	const secret = "monitor-secret-0123456789"
	e := fxNew(t, func(c *config.Config) {
		c.Protection.DefaultAction = config.ActionAllow
		c.Protection.BypassHeaders = []config.BypassHeader{{Name: "Monitor", Header: "x-monitor", Value: secret}}
		c.Protection.Webhooks = []config.Webhook{
			{Name: "hook", Enabled: true, URL: hook.URL},
			{Name: "off", Enabled: false, URL: "http://127.0.0.1:1/", OnError: "block"},
		}
		c.Modules = []config.ModuleConfig{{Name: "probe", Enabled: true}}
	})
	if w := e.get("/robots.txt"); w.Code != http.StatusForbidden {
		t.Fatalf("webhook block: %d", w.Code)
	}
	if n := ruleCount(e, "webhook:hook"); n != 1 {
		t.Errorf("webhook:hook counted %d times", n)
	}
	// The bypass header wins over the webhook and the module.
	before := calls.Load()
	for _, p := range []string{"/robots.txt", "/blocked"} {
		r := fxReq(http.MethodGet, p)
		r.Header.Set("X-Monitor", secret)
		if w := e.do(r); !e.proxied(w) {
			t.Errorf("bypass %s: %d", p, w.Code)
		}
	}
	if calls.Load() != before {
		t.Errorf("the webhook was asked about a bypassed request")
	}
	if n := ruleCount(e, "bypass:Monitor"); n != 2 {
		t.Errorf("bypass:Monitor counted %d times", n)
	}
	r := fxReq(http.MethodGet, "/blocked")
	r.Header.Set("X-Monitor", "wrong-secret-0123456789")
	if w := e.do(r); w.Code != http.StatusForbidden {
		t.Errorf("a wrong bypass value must not bypass: %d", w.Code)
	}
	// A failing webhook follows on_error.
	if w := e.get("/down"); !e.proxied(w) {
		t.Errorf("webhook error with on_error continue: %d", w.Code)
	}
	if err := e.s.mgr.Update(func(c *config.Config) error {
		c.Protection.Webhooks[0].OnError = "block"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if w := e.get("/down"); w.Code != http.StatusForbidden {
		t.Errorf("webhook error with on_error block: %d", w.Code)
	}
}

func TestRateLimitPerSite(t *testing.T) {
	e := fxNew(t, func(c *config.Config) {
		c.Protection.DefaultAction = config.ActionAllow
		c.Protection.RateLimit = config.RateLimit{Enabled: true, Requests: 3, WindowSeconds: 60, Action: "block"}
		own := c.Protection
		own.RateLimit.Requests = 1
		c.Sites = []config.Site{{Name: "Shop", Hosts: []string{"shop.test"}, OwnProtection: true, Protection: own}}
	})
	now := time.Now()
	e.s.now = func() time.Time { return now }
	for i := 0; i < 3; i++ {
		if w := e.get("/"); !e.proxied(w) {
			t.Fatalf("request %d under the limit: %d", i+1, w.Code)
		}
	}
	if w := e.get("/"); w.Code != http.StatusForbidden {
		t.Fatalf("over the limit: %d", w.Code)
	}
	if n := ruleCount(e, "ratelimit"); n != 1 {
		t.Errorf("ratelimit counted %d times", n)
	}
	// Another address has its own count.
	r := fxReq(http.MethodGet, "/")
	r.RemoteAddr = "192.0.2.99:1"
	if w := e.do(r); !e.proxied(w) {
		t.Errorf("another IP: %d", w.Code)
	}
	// A site with its own protection has its own limit and counters.
	shop := func() *httptest.ResponseRecorder {
		r := fxReq(http.MethodGet, "/")
		r.Host = "shop.test"
		return e.do(r)
	}
	if w := shop(); !e.proxied(w) {
		t.Fatalf("shop first request: %d", w.Code)
	}
	if w := shop(); w.Code != http.StatusForbidden {
		t.Errorf("shop over its own limit: %d", w.Code)
	}
	// Counters survive an unrelated config change, and the window slides.
	if err := e.s.mgr.Update(func(c *config.Config) error { c.Protection.Difficulty = 2; return nil }); err != nil {
		t.Fatal(err)
	}
	if w := e.get("/"); w.Code != http.StatusForbidden {
		t.Errorf("an unrelated config change reset the counters: %d", w.Code)
	}
	now = now.Add(3 * time.Minute)
	if w := e.get("/"); !e.proxied(w) {
		t.Errorf("after the window: %d", w.Code)
	}
}
