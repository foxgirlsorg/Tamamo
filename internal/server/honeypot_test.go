package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/foxgirlsorg/tamamo/internal/config"
)

func TestHoneypot(t *testing.T) {
	e := fxNew(t, func(c *config.Config) {
		c.Protection.DefaultAction = config.ActionAllow
		c.Protection.PassHours = 2
		c.Protection.UnprotectedPaths = []string{"/robots.txt"}
		c.Protection.Honeypot = config.Honeypot{Enabled: true, Paths: []string{"/wp-login.php", "/.env", "/admin/*"}}
		// A site whose honeypot is off ignores bans and traps.
		own := c.Protection
		own.Honeypot.Enabled = false
		c.Sites = []config.Site{{Name: "Calm", Hosts: []string{"calm.test"}, OwnProtection: true, Protection: own}}
	})
	now := time.Now()
	e.s.now = func() time.Time { return now }
	from := func(ip, target string) *httptest.ResponseRecorder {
		r := fxReq(http.MethodGet, target)
		r.RemoteAddr = ip + ":1"
		return e.do(r)
	}

	if w := e.get("/"); !e.proxied(w) {
		t.Fatalf("before the trap: %d", w.Code)
	}
	if w := e.get("/wp-login.php"); w.Code != http.StatusForbidden || e.proxied(w) {
		t.Fatalf("trap path: %d, want 403", w.Code)
	}
	if n := ruleCount(e, "honeypot"); n != 1 {
		t.Errorf("honeypot counted %d times, want 1", n)
	}
	// Banned now: every page, unprotected ones included.
	for _, p := range []string{"/", "/robots.txt", "/about"} {
		if w := e.get(p); w.Code != http.StatusForbidden {
			t.Errorf("banned client, %s: %d, want 403", p, w.Code)
		}
	}
	if n := ruleCount(e, "honeypot ban"); n != 3 {
		t.Errorf("honeypot ban counted %d times, want 3", n)
	}
	// Others are not affected, nor is a site with the honeypot off.
	if w := from("192.0.2.99", "/"); !e.proxied(w) {
		t.Errorf("another IP: %d", w.Code)
	}
	calm := fxReq(http.MethodGet, "/wp-login.php")
	calm.Host = "calm.test"
	if w := e.do(calm); !e.proxied(w) {
		t.Errorf("site with the honeypot off: %d", w.Code)
	}

	// The ban lasts pass_hours (ban_hours is 0).
	now = now.Add(2*time.Hour - time.Minute)
	if w := e.get("/"); w.Code != http.StatusForbidden {
		t.Errorf("just before the ban ends: %d", w.Code)
	}
	now = now.Add(2 * time.Minute)
	if w := e.get("/"); !e.proxied(w) {
		t.Errorf("after the ban: %d", w.Code)
	}

	// Patterns, and the other reading of an encoded path, are traps too.
	if w := from("192.0.2.20", "/admin/config.php"); w.Code != http.StatusForbidden {
		t.Errorf("pattern trap: %d", w.Code)
	}
	r := fxRaw("/static/..%2F.env")
	r.RemoteAddr = "192.0.2.21:1"
	if w := e.do(r); w.Code != http.StatusForbidden {
		t.Errorf("encoded trap path: %d", w.Code)
	}
	if w := from("192.0.2.21", "/"); w.Code != http.StatusForbidden {
		t.Errorf("after an encoded trap path: %d, want banned", w.Code)
	}

	// IPv6 clients are banned by /64.
	from("2001:db8:1:2::1", "/.env")
	if w := from("2001:db8:1:2::ffff", "/"); w.Code != http.StatusForbidden {
		t.Errorf("same /64: %d, want banned", w.Code)
	}
	if w := from("2001:db8:1:3::1", "/"); !e.proxied(w) {
		t.Errorf("other /64: %d", w.Code)
	}
}

func TestHoneypotBanHoursAndTrustedProxies(t *testing.T) {
	e := fxNew(t, func(c *config.Config) {
		c.Protection.DefaultAction = config.ActionAllow
		c.Protection.Honeypot = config.Honeypot{Enabled: true, Paths: []string{"/trap"}, BanHours: 1}
		c.Server.TrustedProxies = []string{"198.51.100.0/24"}
	})
	now := time.Now()
	e.s.now = func() time.Time { return now }

	e.get("/trap")
	now = now.Add(61 * time.Minute)
	if w := e.get("/"); !e.proxied(w) {
		t.Errorf("ban_hours 1, after an hour: %d", w.Code)
	}

	// A trusted proxy is never banned: that would ban everyone behind it.
	r := fxReq(http.MethodGet, "/trap")
	r.RemoteAddr = "198.51.100.7:1"
	if w := e.do(r); w.Code == http.StatusForbidden {
		t.Errorf("trap from a trusted proxy: %d, want not banned", w.Code)
	}
	r = fxReq(http.MethodGet, "/")
	r.RemoteAddr = "198.51.100.7:1"
	if w := e.do(r); !e.proxied(w) {
		t.Errorf("trusted proxy after a trap: %d", w.Code)
	}

	// A broken pattern is refused when saving.
	if err := e.s.mgr.Update(func(c *config.Config) error {
		c.Protection.Honeypot.Paths = []string{"re:("}
		return nil
	}); err == nil {
		t.Error("a broken honeypot path pattern was accepted")
	}
}
