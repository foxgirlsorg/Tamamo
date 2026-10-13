package core

import (
	"net/http/httptest"
	"net/netip"
	"testing"
)

func TestClientIPSpecialRemoteAddrs(t *testing.T) {
	for remote, want := range map[string]string{
		"@":                  "invalid IP",
		"":                   "invalid IP",
		"upstream:80":        "invalid IP",
		"/run/app.sock":      "invalid IP",
		"[fe80::1%eth0]:80":  "fe80::1",
		"[::ffff:1.2.3.4]:1": "1.2.3.4",
		"192.0.2.1":          "192.0.2.1",
		"[2001:db8::1]:443":  "2001:db8::1",
	} {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = remote
		if got := ClientIP(r, SourceRemote, nil).String(); got != want {
			t.Errorf("RemoteAddr %q: %s, want %s", remote, got, want)
		}
		// A header source never panics on an unparsable peer and does not
		// trust it when a proxy list is configured.
		r.Header.Set("X-Forwarded-For", "6.6.6.6")
		got := ClientIP(r, SourceXForwardedFor, []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")})
		if want == "invalid IP" && got.IsValid() {
			t.Errorf("RemoteAddr %q: untrusted header used: %s", remote, got)
		}
	}
}

func TestClientIPXFFForms(t *testing.T) {
	proxies := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("127.0.0.1/32")}
	for _, tc := range []struct{ xff, want string }{
		{"1.1.1.1,10.0.0.1", "1.1.1.1"},
		{"1.1.1.1, 10.0.0.1, 127.0.0.1", "1.1.1.1"},
		{"  1.1.1.1  ,  10.0.0.1 ", "1.1.1.1"},
		{"1.2.3.4:5678", "1.2.3.4"},
		{"[2001:db8::5]", "2001:db8::5"},
		{"[2001:db8::5]:443, 10.0.0.2", "2001:db8::5"},
		{"::ffff:101:101", "1.1.1.1"},
		{"6.6.6.6, 1.1.1.1, nonsense, 10.0.0.1", "127.0.0.1"},
		{"", "127.0.0.1"},
	} {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = "127.0.0.1:80"
		if tc.xff != "" {
			r.Header.Set("X-Forwarded-For", tc.xff)
		}
		got := ClientIP(r, SourceXForwardedFor, proxies)
		// Garbage stops the walk: what is left of it can't be trusted, so
		// the result must never be 6.6.6.6 or 1.1.1.1 for the garbage case.
		if tc.want == "127.0.0.1" && tc.xff != "" {
			if s := got.String(); s == "6.6.6.6" || s == "1.1.1.1" {
				t.Errorf("XFF %q: used an address left of garbage: %s", tc.xff, s)
			}
			continue
		}
		if got.String() != tc.want {
			t.Errorf("XFF %q: %s, want %s", tc.xff, got, tc.want)
		}
	}
}
