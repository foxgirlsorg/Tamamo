package server

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tamamo/tamamo/internal/config"
	"github.com/tamamo/tamamo/internal/core"
)

// ---- redirect / open-redirect security ---------------------------------------

// fxStaysOnSite reports whether a browser following target from
// https://example.com/ would stay on example.com. Browsers drop tabs and
// newlines from URLs and treat a backslash like a slash.
func fxStaysOnSite(target string) bool {
	if target == "" || target[0] != '/' {
		return false
	}
	cleaned := strings.Map(func(r rune) rune {
		switch r {
		case '\t', '\n', '\r':
			return -1
		case '\\':
			return '/'
		}
		return r
	}, target)
	if strings.HasPrefix(cleaned, "//") {
		return false
	}
	u, err := url.Parse(cleaned)
	if err != nil {
		// Unparsable but starts with a single "/": a path on this site.
		return true
	}
	base, _ := url.Parse("https://example.com/start")
	res := base.ResolveReference(u)
	return u.Scheme == "" && u.Host == "" && res.Host == "example.com"
}

var fxEvilRedirects = []string{
	// lib/redirect_security_test.go:TestValidateRedirect (invalid / foreign ones)
	"https://evil.com/",
	"https://allowed.example@evil.com/",
	"https:///evil.com/",
	"http:/evil.com/",
	"https:evil.com",
	"//evil.com",
	"//allowed.example",
	"///evil.com",
	"////evil.com",
	"/%2Fevil.com",
	"/%2F%2Fevil.com",
	"/%5Cevil.com",
	`/\evil.com`,
	`https://allowed.example\@evil.com/`,
	" https://evil.com/",
	"/\tevil.com",
	"/\t/evil.com",
	"/\n/evil.com",
	"javascript:alert(1)",
	"data:text/plain,test",
	"file:///etc/passwd",
	"/%zz",
	// lib/redirect_security_test.go:TestRedirectHandlersRejectAmbiguousTargets (decoded wire values)
	"/%252Fevil.com",
	"/%255Cevil.com",
	"%20https://evil.com",
	"/%09/evil.com",
	// lib/redirect_security_test.go:TestRedirectSecurity
	"vbscript:msgbox(1)",
	"data:text/html,<script>alert(1)</script>",
	"https://evil.com/phishing",
	// lib/http_test.go:TestRejectsHostlessRedirect
	"//evil.example/phish",
	"relative/path",
	"",
}

func TestSafeRedirectRejectsAmbiguousTargets(t *testing.T) {
	for _, in := range fxEvilRedirects {
		got := safeRedirect(in)
		if !fxStaysOnSite(got) {
			t.Errorf("safeRedirect(%q) = %q, which leaves the site", in, got)
		}
		if strings.Contains(in, ":") && !strings.HasPrefix(in, "/") && got != "/" {
			t.Errorf("safeRedirect(%q) = %q, want / for an absolute or scheme URL", in, got)
		}
	}
}

func TestSafeRedirectKeepsAllowedDestination(t *testing.T) {
	for _, target := range []string{"/safe%2Fpath?q=%2F%2Fevil.com#fragment", "/foo/bar", "/safe/path", "/", "/a?b=c&d=e"} {
		if got := safeRedirect(target); got != target {
			t.Errorf("safeRedirect(%q) = %q, want it unchanged", target, got)
		}
	}
}

func TestVerifyRedirectIsSanitised(t *testing.T) {
	e := fxNew(t, nil)
	for _, target := range fxEvilRedirects {
		t.Run(target, func(t *testing.T) {
			c := e.challengeClaims()
			w := e.verify(map[string]any{"token": e.signChallenge(c), "nonce": fxSolve(t, c), "redirect": target})
			if w.Code != http.StatusOK {
				t.Fatalf("verify: %d %s", w.Code, w.Body)
			}
			if !strings.Contains(w.Header().Get("Cache-Control"), "no-store") {
				t.Errorf("verify response is cacheable: %q", w.Header().Get("Cache-Control"))
			}
			var out struct {
				OK       bool   `json:"ok"`
				Redirect string `json:"redirect"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
				t.Fatal(err)
			}
			if !out.OK || !fxStaysOnSite(out.Redirect) {
				t.Errorf("redirect %q answered with %q", target, out.Redirect)
			}
			for _, bad := range []string{"javascript:", "vbscript:", "data:", "<script"} {
				if strings.Contains(strings.ToLower(w.Body.String()), bad) {
					t.Errorf("response body echoes %q: %s", bad, w.Body)
				}
			}
		})
	}
	if v := e.verify(map[string]any{"token": "x", "nonce": "1", "redirect": "javascript:alert(1)"}); strings.Contains(v.Body.String(), "javascript") {
		t.Errorf("failed verify echoes the redirect: %s", v.Body)
	}
}

func TestChallengePageDoesNotEmbedOffsiteRedirect(t *testing.T) {
	e := fxNew(t, nil)
	for _, target := range []string{"//evil.example/phish", "///evil.example/phish"} {
		t.Run(target, func(t *testing.T) {
			w := e.get(target)
			if w.Code != http.StatusOK || e.proxied(w) {
				t.Fatalf("want checking page, got %d", w.Code)
			}
			fxCheck(t, strings.Contains(w.Body.String(), "evil.example"),
				"the checking page for request URI %q embeds it unsanitised as the redirect/continue link (Server.challenge uses dc.uri without safeRedirect; only solver.js sanitises it client-side)", target)
		})
	}
}

func TestRenderOnlyRedirectSecurity(t *testing.T) {
	e := fxNew(t, func(c *config.Config) { c.Protection.DefaultAction = config.ActionAllow })
	render := func(uri string, hdr map[string]string) *http.Response {
		r := fxReq(http.MethodGet, "/")
		r.Header.Set(RenderHeader, "1")
		r.Header.Set("X-Original-URI", uri)
		for k, v := range hdr {
			r.Header.Set(k, v)
		}
		return e.do(r).Result()
	}
	for _, target := range []string{"javascript:alert(1)", "//evil.com/", "https://evil.com/x", `/\evil.com`, "/\t/evil.com", "data:text/html,<script>alert(1)</script>"} {
		resp := render(target, map[string]string{"X-Forwarded-Proto": "javascript", "X-Forwarded-Host": "evil.com"})
		loc := resp.Header.Get("Location")
		if resp.StatusCode != http.StatusFound || !fxStaysOnSite(loc) || strings.Contains(loc, "javascript") {
			t.Errorf("X-Original-URI %q: %d Location %q", target, resp.StatusCode, loc)
		}
		if resp.Header.Get("Cache-Control") != "no-store" {
			t.Errorf("X-Original-URI %q: redirect is cacheable", target)
		}
	}
	if resp := render("/protected/page?x=1", nil); resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/protected/page?x=1" {
		t.Errorf("valid redirect: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if e.up.count() != 0 {
		t.Errorf("render-only requests were proxied %d times", e.up.count())
	}
}

// ---- path security -------------------------------------------------------------

func fxAdminBlockConfig(c *config.Config) {
	c.Rules = []config.Rule{
		fxRule("admin", config.ActionBlock, config.Match{Paths: []string{"/admin", "/admin/*"}}),
		fxRule("public", config.ActionAllow, config.Match{Paths: []string{"/*"}}),
	}
}

var fxAmbiguousAdminPaths = []string{
	"/foo/%2e%2e/admin/secret",
	"/foo/%2E%2E/admin/secret",
	"//admin/secret",
	"/admin/./secret",
	"/public/../admin",
	"/public/../admin/secret",
	"/public//../admin",
	"/admin//./secret",
	"/%61dmin/secret",
}

func TestAmbiguousPathCannotBypassBlock(t *testing.T) {
	for _, p := range fxAmbiguousAdminPaths {
		t.Run(p, func(t *testing.T) {
			e := fxNew(t, fxAdminBlockConfig)
			w := e.get(p)
			fxCheck(t, e.up.count() != 0,
				"request path %q reached the upstream as %q although it addresses /admin, which a block rule covers: rules are matched against the raw escaped request URI (dot segments, %%-encoded letters and repeated slashes are not normalized), so an upstream that normalizes paths serves the blocked page", p, e.up.last().uri)
			if w.Code != http.StatusForbidden && w.Code != http.StatusOK {
				t.Errorf("%q: unexpected status %d", p, w.Code)
			}
			if w.Header().Get("Cache-Control") != "no-store" {
				t.Errorf("cache headers for %q: %v", p, w.Header())
			}
		})
	}
}

func TestAuthRequestAmbiguousPathCannotBypassBlock(t *testing.T) {
	for _, header := range []string{"X-Original-URI", "X-Forwarded-Uri"} {
		for _, p := range append([]string{"/public//%2e%2e/admin", "/admin//%2e/secret"}, fxAmbiguousAdminPaths...) {
			t.Run(header+" "+p, func(t *testing.T) {
				e := fxNew(t, fxAdminBlockConfig)
				r := fxReq(http.MethodGet, AuthURL)
				r.Header.Set(header, p)
				w := e.do(r)
				fxCheck(t, w.Code == http.StatusNoContent,
					"auth_request for %s %q answers 204 although the path addresses /admin, which a block rule covers (nginx forwards $request_uri un-normalized but serves the normalized path)", header, p)
			})
		}
	}
}

func TestRepeatedSlashesStillMatchPathRules(t *testing.T) {
	for _, target := range []string{"//admin/secret", "/admin//secret"} {
		for _, header := range []string{"", "X-Original-URI", "X-Forwarded-Uri"} {
			t.Run(target+" "+header, func(t *testing.T) {
				e := fxNew(t, func(c *config.Config) {
					c.Protection.DefaultAction = config.ActionAllow
					c.Rules = []config.Rule{fxRule("secret", config.ActionBlock, config.Match{Paths: []string{"/admin/secret"}})}
				})
				var code int
				if header == "" {
					code = e.get(target).Code
				} else {
					r := fxReq(http.MethodGet, AuthURL)
					r.Header.Set(header, target+"?next=/public")
					code = e.do(r).Code
				}
				fxCheck(t, code != http.StatusForbidden,
					"path %q (via %q) is not matched by the block rule for /admin/secret (got %d): repeated slashes are not collapsed before rule matching", target, header, code)
			})
		}
	}
}

func TestSpoofedOriginalURIIgnoredInProxyMode(t *testing.T) {
	e := fxNew(t, func(c *config.Config) {
		c.Protection.DefaultAction = config.ActionAllow
		c.Rules = []config.Rule{fxRule("admin", config.ActionBlock, config.Match{Paths: []string{"/admin/*"}})}
	})
	for _, h := range []string{"X-Original-URI", "X-Forwarded-Uri"} {
		r := fxReq(http.MethodGet, "/admin/secret")
		r.Header.Set(h, "/public/index")
		if w := e.do(r); w.Code != http.StatusForbidden || e.proxied(w) {
			t.Errorf("spoofed %s let /admin/secret through: %d", h, w.Code)
		}
		r = fxReq(http.MethodGet, "/public/index")
		r.Header.Set(h, "/admin/secret")
		if w := e.do(r); !e.proxied(w) {
			t.Errorf("spoofed %s blocked /public/index: %d", h, w.Code)
		}
	}
	// A visitor sending the render-only header themselves is never proxied.
	before := e.up.count()
	r := fxReq(http.MethodGet, "/admin/secret")
	r.Header.Set(RenderHeader, "1")
	r.Header.Set("X-Original-URI", "/public/index")
	e.do(r)
	if e.up.count() != before {
		t.Error("render-only request was proxied")
	}
}

func TestPathRulesIgnoreQuery(t *testing.T) {
	e := fxNew(t, func(c *config.Config) {
		c.Protection.DefaultAction = config.ActionAllow
		c.Rules = []config.Rule{
			fxRule("admin", config.ActionBlock, config.Match{Paths: []string{"/admin"}}),
			fxRule("public", config.ActionAllow, config.Match{Paths: []string{"/public"}}),
		}
	})
	r := fxReq(http.MethodGet, AuthURL)
	r.Header.Set("X-Original-URI", "/admin?foo=bar")
	if w := e.do(r); w.Code != http.StatusForbidden {
		t.Errorf("auth /admin?foo=bar: %d", w.Code)
	}
	if w := e.get("/admin?next=/public"); w.Code != http.StatusForbidden {
		t.Errorf("GET /admin?next=/public: %d", w.Code)
	}
	if w := e.get("/public?x=/admin"); !e.proxied(w) {
		t.Errorf("GET /public?x=/admin: %d", w.Code)
	}
}

func TestReservedPrefixNeverProxied(t *testing.T) {
	e := fxNew(t, func(c *config.Config) { c.Protection.DefaultAction = config.ActionAllow })
	secret := e.s.mgr.Get().Secret
	for _, p := range []string{
		"/.tamamo/", "/.tamamo/unknown", "/.tamamo/static/", "/.tamamo/static/page.html", "/.tamamo/static/PAGE.HTML",
		"/.tamamo/static/../../config.json", "/.tamamo/static/%2e%2e/page.html", "/.tamamo/static/.hidden",
		"/.tamamo/static/img/../../config.json", "/.tamamo/static/img/..%2fconfig.json", "/.tamamo/static/img/%2e%2e%2fconfig.json",
		"/.tamamo/static/img/config.json", "/.tamamo/static/img/", "/.tamamo/api/", "/%2etamamo/unknown",
	} {
		w := e.get(p)
		if w.Code != http.StatusNotFound {
			t.Errorf("%s: %d, want 404", p, w.Code)
		}
		if secret != "" && strings.Contains(w.Body.String(), secret) {
			t.Errorf("%s: response contains the signing secret", p)
		}
	}
	if e.up.count() != 0 {
		t.Errorf("reserved paths were proxied %d times", e.up.count())
	}
	for _, c := range []struct{ method, path, allow string }{
		{http.MethodPost, HealthURL, "GET, HEAD"},
		{http.MethodPost, AuthURL, "GET, HEAD"},
		{http.MethodGet, VerifyURL, "POST"},
		{http.MethodPut, VerifyURL, "POST"},
		{http.MethodHead, VerifyURL, "POST"},
		{http.MethodDelete, StaticURL + "/solver.js", "GET, HEAD"},
	} {
		w := e.do(fxReq(c.method, c.path))
		if w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") != c.allow {
			t.Errorf("%s %s: %d Allow=%q", c.method, c.path, w.Code, w.Header().Get("Allow"))
		}
	}
	if e.up.count() != 0 {
		t.Errorf("reserved paths were proxied %d times", e.up.count())
	}
}

// ---- header rule security --------------------------------------------------------

func TestHeaderRulesReadAllValues(t *testing.T) {
	e := fxNew(t, func(c *config.Config) {
		c.Protection.DefaultAction = config.ActionAllow
		c.Rules = []config.Rule{fxRule("evil", config.ActionBlock, config.Match{Headers: []config.HeaderMatch{{Name: "x-test", Pattern: "evil"}}})}
	})
	r := fxReq(http.MethodGet, "/")
	r.Header.Add("X-Test", "benign")
	r.Header.Add("X-Test", "evil")
	if w := e.do(r); w.Code != http.StatusForbidden {
		t.Fatalf("second header value ignored: %d", w.Code)
	}
}

func TestAnchoredHeaderRulesReadEachValue(t *testing.T) {
	for _, values := range [][]string{{"evil"}, {"benign", "evil"}, {"evil", "benign"}} {
		t.Run(strings.Join(values, ","), func(t *testing.T) {
			e := fxNew(t, func(c *config.Config) {
				c.Protection.DefaultAction = config.ActionAllow
				c.Rules = []config.Rule{fxRule("evil", config.ActionBlock, config.Match{Headers: []config.HeaderMatch{{Name: "X-Test", Pattern: "re:^evil$"}}})}
			})
			r := fxReq(http.MethodGet, "/")
			r.Header["X-Test"] = values
			w := e.do(r)
			if len(values) == 1 && w.Code != http.StatusForbidden {
				t.Fatalf("single value not matched: %d", w.Code)
			}
			fxCheck(t, w.Code != http.StatusForbidden,
				"header values %q evade the anchored block rule re:^evil$ (got %d): header conditions are matched against all values joined with \", \" instead of each value", values, w.Code)
		})
	}
}

// ---- challenge validation security ----------------------------------------------

func TestInvalidProofRejected(t *testing.T) {
	e := fxNew(t, nil)
	c := e.challengeClaims()
	c.D = 4
	tok := e.signChallenge(c)
	w := e.verify(map[string]any{"token": tok, "nonce": fxWrongNonce(c), "redirect": "/"})
	if w.Code != http.StatusForbidden || e.passCookie(w) != nil || !strings.Contains(w.Body.String(), `"ok":false`) {
		t.Fatalf("invalid proof accepted: %d %s", w.Code, w.Body)
	}
	if w.Code == http.StatusFound {
		t.Fatal("regression on CVE-2025-24369")
	}
	// The challenge is still usable with the right answer.
	if ok := e.verify(map[string]any{"token": tok, "nonce": fxSolve(t, c)}); ok.Code != http.StatusOK || e.passCookie(ok) == nil {
		t.Fatalf("correct answer after a wrong one: %d %s", ok.Code, ok.Body)
	}
}

func TestInvalidProofDoesNotRevealDigest(t *testing.T) {
	e := fxNew(t, nil)
	c := e.challengeClaims()
	c.D = 6
	nonce := fxWrongNonce(c)
	hash, _ := core.CheckPoW(c.R, nonce, c.D)
	w := e.verify(map[string]any{"token": e.signChallenge(c), "nonce": nonce})
	if w.Code != http.StatusForbidden {
		t.Fatalf("got %d", w.Code)
	}
	if strings.Contains(w.Body.String(), hash) || strings.Contains(w.Body.String(), hash[:16]) {
		t.Fatalf("response reveals the computed digest: %s", w.Body)
	}
}

func TestTamperedChallengeRejected(t *testing.T) {
	e := fxNew(t, nil)
	b64 := base64.RawURLEncoding
	cases := map[string]func() (string, string){
		"lowered difficulty, old signature": func() (string, string) {
			c := e.challengeClaims()
			c.D = 6
			tok := e.signChallenge(c)
			_, sig, _ := strings.Cut(tok, ".")
			c.D = 1
			payload, _ := json.Marshal(c)
			return b64.EncodeToString(payload) + "." + sig, fxSolve(t, c)
		},
		"other site, old signature": func() (string, string) {
			c := e.challengeClaims()
			c.S = "other"
			tok := e.signChallenge(c)
			_, sig, _ := strings.Cut(tok, ".")
			c.S = config.DefaultSiteID
			payload, _ := json.Marshal(c)
			return b64.EncodeToString(payload) + "." + sig, fxSolve(t, c)
		},
		"flipped signature": func() (string, string) {
			c := e.challengeClaims()
			tok := []byte(e.signChallenge(c))
			if tok[len(tok)-2] == 'A' {
				tok[len(tok)-2] = 'B'
			} else {
				tok[len(tok)-2] = 'A'
			}
			return string(tok), fxSolve(t, c)
		},
		"signed as a pass": func() (string, string) {
			c := e.challengeClaims()
			return e.s.state().pass.Sign(c), fxSolve(t, c)
		},
		"other secret": func() (string, string) {
			c := e.challengeClaims()
			return core.NewSigner("not the secret", purposeChallenge).Sign(c), fxSolve(t, c)
		},
		"expired": func() (string, string) {
			c := e.challengeClaims()
			c.E = e.s.now().Add(-time.Second).Unix()
			return e.signChallenge(c), fxSolve(t, c)
		},
		"wrong site": func() (string, string) {
			c := e.challengeClaims()
			c.S = "some-other-site"
			return e.signChallenge(c), fxSolve(t, c)
		},
		"wrong IP network": func() (string, string) {
			c := e.challengeClaims()
			c.B = e.bind("198.51.100.10", fxUA)
			return e.signChallenge(c), fxSolve(t, c)
		},
		"wrong user agent": func() (string, string) {
			c := e.challengeClaims()
			c.B = e.bind(fxIP, "curl/8")
			return e.signChallenge(c), fxSolve(t, c)
		},
		"unbound": func() (string, string) {
			c := e.challengeClaims()
			c.B = "-"
			return e.signChallenge(c), fxSolve(t, c)
		},
		"difficulty zero": func() (string, string) {
			c := e.challengeClaims()
			c.D = 0
			return e.signChallenge(c), "0"
		},
		"negative difficulty": func() (string, string) {
			c := e.challengeClaims()
			c.D = -1
			return e.signChallenge(c), "0"
		},
		"empty token": func() (string, string) { return "", "0" },
		"garbage":     func() (string, string) { return "x.y", "0" },
		"no signature": func() (string, string) {
			tok := e.signChallenge(e.challengeClaims())
			p, _, _ := strings.Cut(tok, ".")
			return p, "0"
		},
		"oversize": func() (string, string) {
			c := e.challengeClaims()
			c.R = strings.Repeat("a", 5000)
			return e.signChallenge(c), fxSolve(t, c)
		},
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			tok, nonce := mk()
			w := e.verify(map[string]any{"token": tok, "nonce": nonce, "redirect": "/"})
			if w.Code != http.StatusForbidden || e.passCookie(w) != nil {
				t.Errorf("%s accepted: %d %s", name, w.Code, w.Body)
			}
		})
	}
}

func TestMalformedNonceRejected(t *testing.T) {
	e := fxNew(t, nil)
	c := e.challengeClaims()
	c.D = 8 // no accidental solutions
	tok := e.signChallenge(c)
	for _, raw := range []string{
		`""`, `"-1"`, `"1.5"`, `"1e3"`, `" 1"`, `"1 "`, `"+1"`, `"0x10"`, `"١٢"`, `"12345678901234567"`,
		`"1\u0000"`, `true`, `null`, `{}`, `[]`, `[1]`, `1.5`, `-1`, `1e3`, `12345678901234567890`,
	} {
		w := e.verify(`{"token":"` + tok + `","nonce":` + raw + `}`)
		if w.Code != http.StatusForbidden || e.passCookie(w) != nil {
			t.Errorf("nonce %s: %d %s", raw, w.Code, w.Body)
		}
	}
	// A numeric JSON nonce is accepted when it is the right answer.
	c = e.challengeClaims()
	if w := e.verify(`{"token":"` + e.signChallenge(c) + `","nonce":` + fxSolve(t, c) + `}`); w.Code != http.StatusOK || e.passCookie(w) == nil {
		t.Errorf("numeric nonce: %d %s", w.Code, w.Body)
	}
}

func TestVerifyBodyLimit(t *testing.T) {
	e := fxNew(t, nil)
	c := e.challengeClaims()
	tok, nonce := e.signChallenge(c), fxSolve(t, c)
	big := e.verify(map[string]any{"token": tok, "nonce": nonce, "redirect": "/" + strings.Repeat("x", 128<<10)})
	if big.Code < 400 || e.passCookie(big) != nil {
		t.Fatalf("oversized body accepted: %d", big.Code)
	}
	multipart := e.verify("--X\r\nContent-Disposition: form-data; name=\"token\"\r\n\r\n"+tok+"\r\n--X--\r\n", func(r *http.Request) {
		r.Header.Set("Content-Type", "multipart/form-data; boundary=X")
	})
	if multipart.Code < 400 || e.passCookie(multipart) != nil {
		t.Fatalf("multipart body accepted: %d", multipart.Code)
	}
	// Rejecting the body did not use up the challenge.
	if ok := e.verify(map[string]any{"token": tok, "nonce": nonce, "redirect": "/"}); ok.Code != http.StatusOK || e.passCookie(ok) == nil {
		t.Fatalf("challenge burnt by a rejected body: %d %s", ok.Code, ok.Body)
	}
}

func TestVerifyMissingFields(t *testing.T) {
	e := fxNew(t, nil)
	c := e.challengeClaims()
	tok := e.signChallenge(c)
	for _, body := range []string{"", "{}", "null", "[]", "not json", `{"nonce":"1"}`, `{"token":"` + tok + `"}`, `{"token":null,"nonce":null}`, `{"token":1,"nonce":"1"}`} {
		w := e.verify(body)
		if w.Code != http.StatusForbidden || e.passCookie(w) != nil {
			t.Errorf("body %q: %d %s", body, w.Code, w.Body)
		}
		if !strings.HasPrefix(w.Header().Get("Content-Type"), "application/json") || w.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("body %q: headers %v", body, w.Header())
		}
	}
}

func TestChallengeSpendIsExclusive(t *testing.T) {
	e := fxNew(t, nil)
	c := e.challengeClaims()
	body := map[string]any{"token": e.signChallenge(c), "nonce": fxSolve(t, c), "redirect": "/"}
	var accepted atomic.Int32
	var wg sync.WaitGroup
	gate := make(chan struct{})
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-gate
			if w := e.verify(body); e.passCookie(w) != nil {
				accepted.Add(1)
			}
		}()
	}
	close(gate)
	wg.Wait()
	if got := accepted.Load(); got != 1 {
		t.Fatalf("one challenge minted %d pass cookies", got)
	}
}

// ---- thresholds / limits -----------------------------------------------------------

func TestFailedVerificationsAreRateLimited(t *testing.T) {
	e := fxNew(t, func(c *config.Config) { c.Protection.MaxFailures = 3 })
	t0 := time.Unix(60*30_000_000, 0) // start of a one-minute window
	now := t0
	e.s.now = func() time.Time { return now }

	from := func(ip string, body any) *http.Response {
		return e.verify(body, func(r *http.Request) {
			if strings.Contains(ip, ":") {
				r.RemoteAddr = "[" + ip + "]:1"
			} else {
				r.RemoteAddr = ip + ":1"
			}
		}).Result()
	}
	solved := func(ip string) map[string]any {
		c := e.challengeClaims()
		c.B = e.bind(ip, fxUA)
		return map[string]any{"token": e.signChallenge(c), "nonce": fxSolve(t, c)}
	}
	bad := map[string]any{"token": "x.y", "nonce": "1"}
	for i := 0; i < 3; i++ {
		if r := from(fxIP, bad); r.StatusCode != http.StatusForbidden {
			t.Fatalf("failure %d: %d", i+1, r.StatusCode)
		}
	}
	r := from(fxIP, solved(fxIP))
	if r.StatusCode != http.StatusTooManyRequests || r.Header.Get("Retry-After") == "" {
		t.Fatalf("limit not applied: %d", r.StatusCode)
	}
	for _, c := range r.Cookies() {
		if c.Name == e.cookieName() {
			t.Fatal("rate-limited request got a pass")
		}
	}
	if r := from("198.51.100.20", solved("198.51.100.20")); r.StatusCode != http.StatusOK {
		t.Errorf("another client was limited: %d", r.StatusCode)
	}

	// IPv6 clients are grouped by /64.
	for i := 0; i < 3; i++ {
		from("2001:db8:1:2::1", bad)
	}
	if r := from("2001:db8:1:2::ffff", bad); r.StatusCode != http.StatusTooManyRequests {
		t.Errorf("same /64 not limited: %d", r.StatusCode)
	}
	if r := from("2001:db8:1:3::1", bad); r.StatusCode != http.StatusForbidden {
		t.Errorf("other /64 limited: %d", r.StatusCode)
	}

	// The limit resets with the next minute.
	now = t0.Add(61 * time.Second)
	if r := from(fxIP, solved(fxIP)); r.StatusCode != http.StatusOK {
		t.Errorf("limit did not reset: %d", r.StatusCode)
	}
}
