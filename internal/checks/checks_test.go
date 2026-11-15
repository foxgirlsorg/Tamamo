package checks

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/foxgirlsorg/tamamo/module"
)

func req(ip string) *module.Request {
	return &module.Request{Site: "default", Method: "GET", Host: "example.org", Path: "/x",
		UserAgent: "ua", IP: netip.MustParseAddr(ip), Header: http.Header{}}
}

func TestRateLimit(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	rl := NewRateLimit(3, time.Minute, 64, 1000)
	rl.SetClock(func() time.Time { return now })
	a, b := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")
	for i := 0; i < 3; i++ {
		if rl.Over(a) {
			t.Fatalf("request %d is under the limit", i+1)
		}
	}
	if !rl.Over(a) {
		t.Fatal("the fourth request is over the limit")
	}
	if rl.Over(b) {
		t.Error("another address has its own count")
	}
	if rl.Over(netip.Addr{}) {
		t.Error("an unknown address is never limited")
	}
	// The window slides: half a window later the old requests still weigh half.
	now = now.Add(90 * time.Second)
	if rl.Over(a) || rl.Over(a) || !rl.Over(a) {
		t.Error("after 1.5 windows the 3 old requests weigh 1.5: two more fit, a third doesn't")
	}
	now = now.Add(5 * time.Minute)
	if rl.Over(a) {
		t.Error("long after the window everything is forgotten")
	}
	// IPv6 addresses are counted per network; mapped IPv4 as IPv4.
	v6 := NewRateLimit(1, time.Minute, 64, 1000)
	if v6.Over(netip.MustParseAddr("2001:db8::1")) || !v6.Over(netip.MustParseAddr("2001:db8::2")) {
		t.Error("two addresses of one /64 share a count")
	}
	if v6.Over(netip.MustParseAddr("2001:db8:0:1::1")) {
		t.Error("another /64 has its own count")
	}
	if v6.Over(netip.MustParseAddr("::ffff:192.0.2.9")) || !v6.Over(netip.MustParseAddr("192.0.2.9")) {
		t.Error("an IPv4-mapped address is the IPv4 address")
	}
}

func TestRateLimitBoundedMemory(t *testing.T) {
	rl := NewRateLimit(10, time.Minute, 64, 100)
	for i := 0; i < 5000; i++ {
		rl.Over(netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}))
	}
	if n := len(rl.buckets); n > 100 {
		t.Errorf("%d buckets tracked, limit is 100", n)
	}
}

func TestBypass(t *testing.T) {
	const secret = "0123456789abcdef-secret"
	b, err := NewBypass("mon", "x-monitor-token", secret)
	if err != nil {
		t.Fatal(err)
	}
	h := http.Header{}
	if b.Match(h) {
		t.Error("no header matched")
	}
	h.Set("X-Monitor-Token", secret+"x")
	if b.Match(h) {
		t.Error("a longer value matched")
	}
	h.Add("X-Monitor-Token", secret)
	if !b.Match(h) {
		t.Error("the secret in a second header line should match")
	}
	for _, bad := range [][2]string{{"", secret}, {"X Bad", secret}, {"X-Ok", "short"}, {"X:Ok", secret}} {
		if _, err := NewBypass("n", bad[0], bad[1]); err == nil {
			t.Errorf("accepted header %q value %q", bad[0], bad[1])
		}
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
			_, _ = io.WriteString(w, `{"action":"block","reason":"nope"}`)
		case "/challenge":
			_, _ = io.WriteString(w, `{"action":"challenge","difficulty":6}`)
		case "/500":
			w.WriteHeader(500)
		case "/badjson":
			_, _ = io.WriteString(w, `{"action":`)
		case "/weird":
			_, _ = io.WriteString(w, `{"action":"explode"}`)
		case "/slow":
			time.Sleep(300 * time.Millisecond)
			_, _ = io.WriteString(w, `{"action":"block"}`)
		case "/redirect":
			http.Redirect(w, r, "/block", http.StatusFound)
		default:
			_, _ = io.WriteString(w, `{}`)
		}
	}))
	defer srv.Close()

	c, err := NewWebhook(WebhookOptions{URL: srv.URL, Timeout: 100 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	check := func(path string) (module.Decision, error) {
		r := req("192.0.2.7")
		r.Path = path
		r.Query = "a=1"
		r.Header.Set("Cookie", "session=secret")
		r.Header.Set("Accept-Language", "ru")
		return c.Check(ctx, r)
	}
	if d, err := check("/block"); err != nil || d.Action != module.Block || d.Reason != "nope" {
		t.Errorf("block: %+v %v", d, err)
	}
	if got.IP != "192.0.2.7" || got.Query != "a=1" || got.Site != "default" || got.UserAgent != "ua" || got.Host != "example.org" {
		t.Errorf("request body %+v", got)
	}
	if got.Headers["Accept-Language"] != "ru" || got.Headers["Cookie"] != "" {
		t.Errorf("headers %v (cookies must not be sent by default)", got.Headers)
	}
	if d, err := check("/challenge"); err != nil || d.Action != module.Challenge || d.Difficulty != 6 {
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
		if d, _ := cc.Check(ctx, r); d.Action != module.Block {
			t.Fatal("cached decision lost")
		}
	}
	if n := calls.Load(); n != 1 {
		t.Errorf("webhook called %d times, want 1", n)
	}
	r.Path = "/challenge"
	_, _ = cc.Check(ctx, r)
	if n := calls.Load(); n != 2 {
		t.Errorf("different path not asked: %d", n)
	}
	cc.now = func() time.Time { return time.Now().Add(2 * time.Minute) }
	_, _ = cc.Check(ctx, r)
	if n := calls.Load(); n != 3 {
		t.Errorf("expired entry reused: %d", n)
	}

	for _, u := range []string{"", "ftp://x", "/relative", "http://", "http://u:p@host/"} {
		if _, err := NewWebhook(WebhookOptions{URL: u}); err == nil {
			t.Errorf("URL %q accepted", u)
		}
	}
}
