package server

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

// The visitor pass lives only in an HttpOnly cookie (Secure over HTTPS) and
// is never part of the verify response body, so page scripts can't read it.
func TestPassCookieFlags(t *testing.T) {
	s, _, _ := setup(t)
	for _, https := range []bool{false, true} {
		w := get(s, "/", browserUA)
		tok, claims := extractChallenge(t, w.Body.String())
		b, _ := json.Marshal(map[string]any{"token": tok, "nonce": solve(t, claims), "redirect": "/"})
		r := httptest.NewRequest("POST", VerifyURL, strings.NewReader(string(b)))
		r.RemoteAddr = "192.0.2.10:5555"
		r.Header.Set("User-Agent", browserUA)
		r.Header.Set("Content-Type", "application/json")
		if https {
			r.Header.Set("X-Forwarded-Proto", "https")
		}
		v := httptest.NewRecorder()
		s.ServeHTTP(v, r)
		if v.Code != 200 {
			t.Fatalf("verify: %d %s", v.Code, v.Body)
		}
		raw := v.Header().Get("Set-Cookie")
		if !strings.Contains(raw, "HttpOnly") || !strings.Contains(raw, "SameSite=Lax") || strings.Contains(raw, "Secure") != https {
			t.Errorf("https=%v: Set-Cookie %q", https, raw)
		}
		val := strings.SplitN(strings.TrimPrefix(raw, "tamamo-pass="), ";", 2)[0]
		if val == "" || strings.Contains(v.Body.String(), val) {
			t.Errorf("the pass appears in the response body: %s", v.Body)
		}
	}
}
