package core

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"testing"
)

func TestSignerRoundtrip(t *testing.T) {
	s := NewSigner("secret", "challenge")
	in := ChallengeClaims{R: "abc", D: 3, E: 12345, B: "-"}
	tok := s.Sign(in)
	if !strings.Contains(tok, ".") {
		t.Fatalf("token %q has no separator", tok)
	}
	var out ChallengeClaims
	if err := s.Verify(tok, &out); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if out != in {
		t.Fatalf("got %+v, want %+v", out, in)
	}
}

func TestSignerTamper(t *testing.T) {
	s := NewSigner("secret", "pass")
	tok := s.Sign(PassClaims{D: 4, E: 99, I: 1, B: "x"})
	payload, sig, _ := strings.Cut(tok, ".")

	// Forge a payload with a higher difficulty but keep the old signature.
	forged := b64.EncodeToString([]byte(`{"d":8,"e":99,"i":1,"b":"x"}`)) + "." + sig
	cases := map[string]string{
		"forged payload": forged,
		"flipped sig":    payload + "." + flip(sig),
		"no sig":         payload,
		"empty":          "",
		"dot only":       ".",
		"bad base64":     payload + ".!!!",
	}
	for name, tk := range cases {
		var c PassClaims
		if err := s.Verify(tk, &c); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	if err := NewSigner("other", "pass").Verify(tok, &PassClaims{}); err == nil {
		t.Error("token verified with a different secret")
	}
}

func flip(s string) string {
	b := []byte(s)
	if b[0] == 'A' {
		b[0] = 'B'
	} else {
		b[0] = 'A'
	}
	return string(b)
}

func TestSignerPurposeSeparation(t *testing.T) {
	chal := NewSigner("secret", "challenge")
	pass := NewSigner("secret", "pass")
	tok := chal.Sign(ChallengeClaims{R: "r", D: 1, E: 1})
	if err := pass.Verify(tok, &PassClaims{}); err == nil {
		t.Fatal("challenge token accepted by pass signer")
	}
}

func solve(t *testing.T, random string, d int) string {
	t.Helper()
	for n := 0; n < 10_000_000; n++ {
		nonce := strconv.Itoa(n)
		if _, ok := CheckPoW(random, nonce, d); ok {
			return nonce
		}
	}
	t.Fatal("no solution found")
	return ""
}

func TestCheckPoW(t *testing.T) {
	random := NewRandom()
	if len(random) != 32 {
		t.Fatalf("random %q should be 32 hex chars", random)
	}
	nonce := solve(t, random, 2)
	hash, ok := CheckPoW(random, nonce, 2)
	if !ok || !strings.HasPrefix(hash, "00") || len(hash) != 64 {
		t.Fatalf("solution rejected: %s %v", hash, ok)
	}
	// Difficulty 0 accepts anything valid.
	if _, ok := CheckPoW(random, "1", 0); !ok {
		t.Error("difficulty 0 should accept any nonce")
	}
	for _, bad := range []string{"", "-1", "1.5", "12345678901234567", " 1", "1e3", "١"} {
		if _, ok := CheckPoW(random, bad, 0); ok {
			t.Errorf("nonce %q should be rejected", bad)
		}
	}
	if _, ok := CheckPoW(random, nonce, 65); ok {
		t.Error("difficulty above 64 should be rejected")
	}
	// A solution for one random does not (in general) solve another; check
	// with a difficulty high enough that a fluke is ~impossible.
	if _, ok := CheckPoW(random+"x", nonce, 8); ok {
		t.Error("unexpected solution for a different random")
	}
}

func TestBindHash(t *testing.T) {
	a := netip.MustParseAddr("192.0.2.10")
	b := netip.MustParseAddr("192.0.2.200")
	c := netip.MustParseAddr("192.0.3.10")
	if BindHash(a, "ua", true, true) != BindHash(b, "ua", true, true) {
		t.Error("addresses in the same /24 should bind equally")
	}
	if BindHash(a, "ua", true, true) == BindHash(c, "ua", true, true) {
		t.Error("addresses in different /24s should differ")
	}
	if BindHash(netip.MustParseAddr("::ffff:192.0.2.10"), "ua", true, false) != BindHash(a, "other", true, false) {
		t.Error("mapped v4 should equal v4, and UA must be ignored when unbound")
	}
	v6a := netip.MustParseAddr("2001:db8:1:2::1")
	v6b := netip.MustParseAddr("2001:db8:1:2:ffff::9")
	v6c := netip.MustParseAddr("2001:db8:1:3::1")
	if BindHash(v6a, "", true, false) != BindHash(v6b, "", true, false) {
		t.Error("addresses in the same /64 should bind equally")
	}
	if BindHash(v6a, "", true, false) == BindHash(v6c, "", true, false) {
		t.Error("addresses in different /64s should differ")
	}
	if BindHash(a, "ua1", false, true) == BindHash(a, "ua2", false, true) {
		t.Error("different UAs should differ")
	}
	if BindHash(a, "ua1", false, true) != BindHash(c, "ua1", false, true) {
		t.Error("IP must be ignored when unbound")
	}
	if h := BindHash(a, "ua", false, false); h != "-" {
		t.Errorf("nothing bound should give -, got %q", h)
	}
	if h := BindHash(a, "ua", true, true); len(h) != 16 {
		t.Errorf("hash %q should be 16 chars", h)
	}
}

func req(remote string, hdr map[string]string) *http.Request {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = remote
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	return r
}

func TestClientIP(t *testing.T) {
	proxies := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	cases := []struct {
		name    string
		remote  string
		hdr     map[string]string
		source  string
		trusted []netip.Prefix
		want    string
	}{
		{"remote", "203.0.113.5:1234", map[string]string{"X-Forwarded-For": "1.1.1.1"}, "remote", nil, "203.0.113.5"},
		{"remote mapped", "[::ffff:203.0.113.5]:1234", nil, "remote", nil, "203.0.113.5"},
		{"remote v6", "[2001:db8::1]:80", nil, "remote", nil, "2001:db8::1"},
		{"xff untrusted peer ignored", "203.0.113.5:1", map[string]string{"X-Forwarded-For": "1.1.1.1"}, "x-forwarded-for", proxies, "203.0.113.5"},
		{"xff trusted peer", "10.0.0.1:1", map[string]string{"X-Forwarded-For": "1.1.1.1"}, "x-forwarded-for", proxies, "1.1.1.1"},
		{"xff skip trusted hops", "10.0.0.1:1", map[string]string{"X-Forwarded-For": "6.6.6.6, 1.1.1.1, 10.0.0.7"}, "x-forwarded-for", proxies, "1.1.1.1"},
		{"xff all trusted", "10.0.0.1:1", map[string]string{"X-Forwarded-For": "10.0.0.9, 10.0.0.7"}, "x-forwarded-for", proxies, "10.0.0.9"},
		{"xff empty trusted rightmost", "203.0.113.5:1", map[string]string{"X-Forwarded-For": "6.6.6.6, 1.1.1.1"}, "x-forwarded-for", nil, "1.1.1.1"},
		{"xff garbage", "10.0.0.1:1", map[string]string{"X-Forwarded-For": "nonsense"}, "x-forwarded-for", proxies, "10.0.0.1"},
		{"xff missing", "10.0.0.1:1", nil, "x-forwarded-for", proxies, "10.0.0.1"},
		{"xff mapped", "10.0.0.1:1", map[string]string{"X-Forwarded-For": "::ffff:1.2.3.4"}, "x-forwarded-for", proxies, "1.2.3.4"},
		{"x-real-ip", "10.0.0.1:1", map[string]string{"X-Real-IP": "1.2.3.4"}, "x-real-ip", proxies, "1.2.3.4"},
		{"x-real-ip untrusted", "8.8.8.8:1", map[string]string{"X-Real-IP": "1.2.3.4"}, "x-real-ip", proxies, "8.8.8.8"},
		{"cf", "10.0.0.1:1", map[string]string{"CF-Connecting-IP": "2001:db8::5"}, "cf-connecting-ip", proxies, "2001:db8::5"},
		{"cf empty trusted", "8.8.8.8:1", map[string]string{"CF-Connecting-IP": "1.2.3.4"}, "cf-connecting-ip", nil, "1.2.3.4"},
	}
	for _, c := range cases {
		got := ClientIP(req(c.remote, c.hdr), c.source, c.trusted)
		if got.String() != c.want {
			t.Errorf("%s: got %s, want %s", c.name, got, c.want)
		}
	}
}

func TestClientIPMultipleXFFLines(t *testing.T) {
	r := req("10.0.0.1:1", nil)
	r.Header.Add("X-Forwarded-For", "6.6.6.6")
	r.Header.Add("X-Forwarded-For", "1.1.1.1, 10.1.1.1")
	got := ClientIP(r, "x-forwarded-for", []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")})
	if got.String() != "1.1.1.1" {
		t.Fatalf("got %s", got)
	}
}
