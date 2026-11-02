package modules

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func req(ip string) Request {
	return Request{Site: "default", Method: "GET", Host: "example.org", Path: "/x",
		UserAgent: "ua", IP: netip.MustParseAddr(ip), Header: http.Header{}}
}

func TestRegistry(t *testing.T) {
	names := map[string]bool{}
	for _, in := range Available() {
		names[in.Name] = true
	}
	if !names["ratelimit"] || !names["bypass-header"] {
		t.Fatalf("built-ins missing: %v", names)
	}
	if _, err := New("nope", nil); err == nil {
		t.Error("unknown module accepted")
	}
	if _, err := New("bypass-header", map[string]string{"header": "X-Token"}); err == nil {
		t.Error("missing required setting accepted")
	}
	defer func() {
		if recover() == nil {
			t.Error("duplicate Register did not panic")
		}
	}()
	Register(Info{Name: "ratelimit"}, newRateLimit)
}

func TestRateLimit(t *testing.T) {
	c, err := New("ratelimit", map[string]string{"requests": "3", "window_seconds": "10", "action": "challenge"})
	if err != nil {
		t.Fatal(err)
	}
	rl := c.(*rateLimit)
	now := time.Unix(1000, 0)
	rl.now = func() time.Time { return now }
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if d, _ := rl.Check(ctx, req("192.0.2.1")); d.Action != "" {
			t.Fatalf("request %d limited: %+v", i, d)
		}
	}
	if d, _ := rl.Check(ctx, req("192.0.2.1")); d.Action != Challenge {
		t.Fatalf("4th request: %+v", d)
	}
	if d, _ := rl.Check(ctx, req("192.0.2.2")); d.Action != "" {
		t.Fatal("other IP limited")
	}
	// IPv6 addresses of one /64 share a counter.
	for i := 0; i < 3; i++ {
		rl.Check(ctx, req("2001:db8::1"))
	}
	if d, _ := rl.Check(ctx, req("2001:db8::ffff")); d.Action != Challenge {
		t.Fatal("same /64 not limited")
	}
	// Half a window later the previous window still weighs in; two windows
	// later the counter is clean.
	now = now.Add(15 * time.Second)
	if d, _ := rl.Check(ctx, req("192.0.2.1")); d.Action != "" {
		// estimate = 3*0.5 + 0 = 1.5 < 3
		t.Fatalf("after 1.5 windows: %+v", d)
	}
	now = now.Add(30 * time.Second)
	for i := 0; i < 3; i++ {
		if d, _ := rl.Check(ctx, req("192.0.2.1")); d.Action != "" {
			t.Fatalf("after reset %d: %+v", i, d)
		}
	}
	if _, err := New("ratelimit", map[string]string{"action": "allow"}); err == nil {
		t.Error("action allow accepted")
	}
	if _, err := New("ratelimit", map[string]string{"requests": "0"}); err == nil {
		t.Error("requests 0 accepted")
	}
}

func TestRateLimitBoundedMemory(t *testing.T) {
	c, _ := New("ratelimit", map[string]string{"max_ips": "100"})
	rl := c.(*rateLimit)
	for i := 0; i < 1000; i++ {
		ip := netip.AddrFrom4([4]byte{10, 0, byte(i >> 8), byte(i)})
		rl.Check(context.Background(), Request{IP: ip})
	}
	if n := len(rl.buckets); n > 100 {
		t.Fatalf("%d buckets tracked, max 100", n)
	}
	if d, _ := rl.Check(context.Background(), Request{}); d.Action != "" {
		t.Fatal("request without IP limited")
	}
}

func TestBypassHeader(t *testing.T) {
	const secret = "0123456789abcdef-secret"
	if _, err := New("bypass-header", map[string]string{"header": "X-Monitor", "value": "short"}); err == nil {
		t.Error("short secret accepted")
	}
	c, err := New("bypass-header", map[string]string{"header": "x-monitor", "value": secret})
	if err != nil {
		t.Fatal(err)
	}
	r := req("192.0.2.1")
	if d, _ := c.Check(context.Background(), r); d.Action != "" {
		t.Fatal("no header allowed")
	}
	r.Header.Set("X-Monitor", secret+"x")
	if d, _ := c.Check(context.Background(), r); d.Action != "" {
		t.Fatal("wrong value allowed")
	}
	r.Header.Add("X-Monitor", secret)
	if d, _ := c.Check(context.Background(), r); d.Action != Allow {
		t.Fatalf("right value: %+v", d)
	}
}

func TestWebhook(t *testing.T) {
	var got WebhookRequest
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("bad request %s %s", r.Method, r.Header.Get("Content-Type"))
		}
		_ = json.NewDecoder(r.Body).Decode(&got)
		switch got.Path {
		case "/block":
			io.WriteString(w, `{"action":"block","reason":"nope"}`)
		case "/challenge":
			io.WriteString(w, `{"action":"challenge","difficulty":6}`)
		case "/500":
			w.WriteHeader(500)
		case "/badjson":
			io.WriteString(w, `{"action":`)
		case "/weird":
			io.WriteString(w, `{"action":"explode"}`)
		case "/slow":
			time.Sleep(300 * time.Millisecond)
			io.WriteString(w, `{"action":"block"}`)
		case "/redirect":
			http.Redirect(w, r, "/block", http.StatusFound)
		default:
			io.WriteString(w, `{}`)
		}
	}))
	defer srv.Close()

	c, err := NewWebhook(WebhookOptions{URL: srv.URL, Timeout: 100 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	check := func(path string) (Decision, error) {
		r := req("192.0.2.7")
		r.Path = path
		r.Query = "a=1"
		r.Header.Set("Cookie", "session=secret")
		r.Header.Set("Accept-Language", "ru")
		return c.Check(ctx, r)
	}
	if d, err := check("/block"); err != nil || d.Action != Block || d.Reason != "nope" {
		t.Errorf("block: %+v %v", d, err)
	}
	if got.IP != "192.0.2.7" || got.Query != "a=1" || got.Site != "default" || got.UserAgent != "ua" || got.Host != "example.org" {
		t.Errorf("request body %+v", got)
	}
	if got.Headers["Accept-Language"] != "ru" || got.Headers["Cookie"] != "" {
		t.Errorf("headers %v (cookies must not be sent by default)", got.Headers)
	}
	if d, err := check("/challenge"); err != nil || d.Action != Challenge || d.Difficulty != 6 {
		t.Errorf("challenge: %+v %v", d, err)
	}
	if d, err := check("/other"); err != nil || d.Action != "" {
		t.Errorf("no opinion: %+v %v", d, err)
	}
	for _, p := range []string{"/500", "/badjson", "/weird", "/slow", "/redirect"} {
		if _, err := check(p); err == nil {
			t.Errorf("%s: no error", p)
		}
	}

	// Caching.
	cc, _ := NewWebhook(WebhookOptions{URL: srv.URL, CacheTTL: time.Minute})
	calls.Store(0)
	r := req("192.0.2.8")
	r.Path = "/block"
	for i := 0; i < 3; i++ {
		if d, _ := cc.Check(ctx, r); d.Action != Block {
			t.Fatal("cached decision lost")
		}
	}
	if n := calls.Load(); n != 1 {
		t.Errorf("webhook called %d times, want 1", n)
	}
	r.Path = "/challenge"
	cc.Check(ctx, r)
	if n := calls.Load(); n != 2 {
		t.Errorf("different path not asked: %d", n)
	}
	wh := cc.(*webhook)
	wh.now = func() time.Time { return time.Now().Add(2 * time.Minute) }
	cc.Check(ctx, r)
	if n := calls.Load(); n != 3 {
		t.Errorf("expired entry reused: %d", n)
	}

	for _, u := range []string{"", "ftp://x", "/relative", "http://", "http://u:p@host/"} {
		if _, err := NewWebhook(WebhookOptions{URL: u}); err == nil {
			t.Errorf("URL %q accepted", u)
		}
	}
}

func TestCloseFragment(t *testing.T) {
	for in, want := range map[string]string{
		`<div class="a">hi`:                     `<div class="a">hi</div>`,
		`<p>one<b>two</p>`:                      `<p>one<b>two</b></p>`,
		`</div></body></html>text`:              `text`,
		`<script>if (a<b) {`:                    `<script>if (a<b) {</script>`,
		`<style>p{}</style><img src=x>`:         `<style>p{}</style><img src=x>`,
		`<!-- open`:                             `<!-- open-->`,
		`<svg><path d="M0"/></svg>`:             `<svg><path d="M0"/></svg>`,
		`a < b`:                                 `a &lt; b`,
		`<span title="a>b">x</span>`:            `<span title="a>b">x</span>`,
		`ok<plaintext>rest`:                     `ok`,
		`<body><textarea>`:                      `<textarea></textarea>`,
		`<template><div></template>`:            `<template><div></div></template>`,
		`<SCRIPT>x</SCRIPT>`:                    `<SCRIPT>x</script>`,
		`<div><a href="/">x</a></div><br><hr/>`: `<div><a href="/">x</a></div><br><hr/>`,
		`<ul><li>one<li>two</ul>`:               `<ul><li>one<li>two</li></li></ul>`,
		`<iframe src="x">`:                      `<iframe src="x"></iframe>`,
		`<div`:                                  ``,
	} {
		if got := CloseFragment(in); got != want {
			t.Errorf("CloseFragment(%q) = %q, want %q", in, got, want)
		}
	}
}

func writeFile(t *testing.T, p, s string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestPageFiles(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "banner", "head.html"), `<meta name="x" content="{module}">`)
	writeFile(t, filepath.Join(dir, "banner", "body.html"), `<div><img src="{module}/logo.svg">`)
	writeFile(t, filepath.Join(dir, "banner", "style.css"), `.x{}`)
	writeFile(t, filepath.Join(dir, "banner", "img", "logo.svg"), `<svg/>`)
	writeFile(t, filepath.Join(dir, "banner", ".secret"), `nope`)
	writeFile(t, filepath.Join(dir, "Bad Name", "head.html"), `x`)
	writeFile(t, filepath.Join(dir, "secret.txt"), `outside`)

	pf, err := LoadPage(dir, "banner")
	if err != nil {
		t.Fatal(err)
	}
	if !pf.Style || pf.Script || pf.Version == "" {
		t.Errorf("files %+v", pf)
	}
	head, body := pf.Snippets("/.tamamo/modules")
	if head != `<meta name="x" content="/.tamamo/modules/banner">` || body != `<div><img src="/.tamamo/modules/banner/logo.svg"></div>` {
		t.Errorf("snippets %q %q", head, body)
	}
	v := pf.Version
	time.Sleep(10 * time.Millisecond)
	writeFile(t, filepath.Join(dir, "banner", "script.js"), `1`)
	if pf, _ = LoadPage(dir, "banner"); !pf.Script || pf.Version == v {
		t.Error("change not picked up")
	}
	if _, err := LoadPage(dir, "missing"); err == nil {
		t.Error("missing module loaded")
	}
	if _, err := LoadPage(dir, "../banner"); err == nil {
		t.Error("bad name loaded")
	}

	ls, err := ListPages(dir)
	if err != nil || len(ls) != 1 || ls[0].Name != "banner" {
		t.Fatalf("listing %+v %v", ls, err)
	}
	if strings.Join(ls[0].Files, ",") != "body.html,head.html,img/logo.svg,script.js,style.css" {
		t.Errorf("files %v", ls[0].Files)
	}
	if ls, _ := ListPages(filepath.Join(dir, "nope")); ls == nil || len(ls) != 0 {
		t.Error("missing dir should list nothing")
	}

	serve := func(name, file string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		ServeFile(w, httptest.NewRequest("GET", "/x", nil), dir, name, file)
		return w
	}
	if w := serve("banner", "style.css"); w.Code != 200 || w.Header().Get("Content-Type") != "text/css; charset=utf-8" || w.Body.String() != ".x{}" {
		t.Errorf("style.css: %d %q", w.Code, w.Header().Get("Content-Type"))
	}
	if w := serve("banner", "img/logo.svg"); w.Code != 200 || w.Header().Get("Content-Type") != "image/svg+xml" ||
		!strings.Contains(w.Header().Get("Content-Security-Policy"), "sandbox") {
		t.Errorf("svg: %d %v", w.Code, w.Header())
	}
	for _, c := range [][2]string{
		{"banner", "head.html"}, {"banner", "body.html"}, {"banner", ".secret"}, {"banner", "../secret.txt"},
		{"banner", "img/../../secret.txt"}, {"..", "secret.txt"}, {"banner", "/etc/passwd"}, {"banner", "img"},
		{"banner", `img\logo.svg`}, {"banner", ""}, {"banner", "img//logo.svg"}, {"Bad Name", "head.html"},
		{"banner", "nope.css"},
	} {
		if w := serve(c[0], c[1]); w.Code != 404 {
			t.Errorf("%s/%s: %d, want 404", c[0], c[1], w.Code)
		}
	}
}
