package config

import (
	"net/http"
	"net/netip"
	"testing"
)

func mustRules(t *testing.T, rules ...Rule) *RuleSet {
	t.Helper()
	rs, err := CompileRules(rules)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return rs
}

func name(r *Rule) string {
	if r == nil {
		return ""
	}
	return r.Name
}

func TestRulePaths(t *testing.T) {
	rs := mustRules(t,
		Rule{Name: "glob", Enabled: true, Action: ActionAllow, Match: Match{Paths: []string{"/api/*", "/exact"}}},
		Rule{Name: "re", Enabled: true, Action: ActionBlock, Match: Match{Paths: []string{`re:^/(wp-admin|xmlrpc\.php)`}}},
	)
	cases := map[string]string{
		"/api/":         "glob",
		"/api/v1/users": "glob",
		"/exact":        "glob",
		"/exact/more":   "",
		"/apix":         "",
		"/x/api/y":      "",
		"/wp-admin/a":   "re",
		"/xmlrpc.php":   "re",
		"/xmlrpcXphp":   "",
		"/EXACT":        "", // paths are case-sensitive
	}
	for p, want := range cases {
		if got := name(rs.Match(RuleRequest{Path: p})); got != want {
			t.Errorf("path %q: got %q, want %q", p, got, want)
		}
	}
}

func TestRuleUserAgentsContainsFold(t *testing.T) {
	rs := mustRules(t,
		Rule{Name: "bot", Enabled: true, Action: ActionBlock, Match: Match{UserAgents: []string{"*GPTBot*"}}},
		Rule{Name: "plain", Enabled: true, Action: ActionBlock, Match: Match{UserAgents: []string{"curl"}}},
	)
	if got := name(rs.Match(RuleRequest{UserAgent: "Mozilla/5.0 (compatible; gptbot/1.0)"})); got != "bot" {
		t.Errorf("case-insensitive glob: got %q", got)
	}
	if got := name(rs.Match(RuleRequest{UserAgent: "my-curl/8"})); got != "plain" {
		t.Errorf("contains match: got %q", got)
	}
	if got := name(rs.Match(RuleRequest{UserAgent: "Firefox"})); got != "" {
		t.Errorf("no match expected, got %q", got)
	}
}

func TestRuleIPs(t *testing.T) {
	rs := mustRules(t,
		Rule{Name: "net", Enabled: true, Action: ActionAllow, Match: Match{IPs: []string{"10.0.0.0/8", "2001:db8::/32", "192.0.2.7"}}},
	)
	cases := map[string]bool{
		"10.1.2.3":        true,
		"::ffff:10.1.2.3": true,
		"11.0.0.1":        false,
		"2001:db8:5::1":   true,
		"2001:db9::1":     false,
		"192.0.2.7":       true,
		"192.0.2.8":       false,
	}
	for ip, want := range cases {
		got := rs.Match(RuleRequest{IP: netip.MustParseAddr(ip)}) != nil
		if got != want {
			t.Errorf("ip %s: got %v, want %v", ip, got, want)
		}
	}
	if rs.Match(RuleRequest{}) != nil {
		t.Error("invalid IP should not match an IP rule")
	}
}

func TestRuleFirstMatchWinsAndDisabled(t *testing.T) {
	rs := mustRules(t,
		Rule{Name: "off", Enabled: false, Action: ActionBlock},
		Rule{Name: "first", Enabled: true, Action: ActionAllow, Match: Match{Paths: []string{"/a*"}}},
		Rule{Name: "second", Enabled: true, Action: ActionBlock, Match: Match{Paths: []string{"/ab"}}},
		Rule{Name: "catchall", Enabled: true, Action: ActionChallenge},
	)
	if got := name(rs.Match(RuleRequest{Path: "/ab"})); got != "first" {
		t.Errorf("got %q, want first", got)
	}
	if got := name(rs.Match(RuleRequest{Path: "/zzz"})); got != "catchall" {
		t.Errorf("got %q, want catchall (disabled rule must be skipped)", got)
	}
}

func TestRuleAllConditionsMustHold(t *testing.T) {
	rs := mustRules(t,
		Rule{Name: "post-api", Enabled: true, Action: ActionBlock, Match: Match{
			Paths: []string{"/api/*"}, Methods: []string{"post"}, Hosts: []string{"*.example.com"},
		}},
	)
	ok := RuleRequest{Method: "POST", Path: "/api/x", Host: "Shop.Example.com:8923"}
	if rs.Match(ok) == nil {
		t.Error("expected match")
	}
	bad := ok
	bad.Method = "GET"
	if rs.Match(bad) != nil {
		t.Error("method should not match")
	}
	bad = ok
	bad.Host = "example.org"
	if rs.Match(bad) != nil {
		t.Error("host should not match")
	}
}

func TestRuleHeaders(t *testing.T) {
	rs := mustRules(t,
		Rule{Name: "hdr", Enabled: true, Action: ActionBlock, Match: Match{Headers: []HeaderMatch{
			{Name: "accept-language", Pattern: "*zz*"},
		}}},
		Rule{Name: "re-hdr", Enabled: true, Action: ActionAllow, Match: Match{Headers: []HeaderMatch{
			{Name: "X-Token", Pattern: `re:^secret-[0-9]+$`},
		}}},
	)
	h := http.Header{}
	h.Set("Accept-Language", "en, ZZ;q=0.5")
	if got := name(rs.Match(RuleRequest{Header: h})); got != "hdr" {
		t.Errorf("got %q, want hdr", got)
	}
	h = http.Header{}
	h.Set("X-Token", "secret-42")
	if got := name(rs.Match(RuleRequest{Header: h})); got != "re-hdr" {
		t.Errorf("got %q, want re-hdr", got)
	}
	h.Set("X-Token", "secret-42x")
	if got := name(rs.Match(RuleRequest{Header: h})); got != "" {
		t.Errorf("got %q, want no match", got)
	}
	if got := name(rs.Match(RuleRequest{Header: http.Header{}})); got != "" {
		t.Errorf("missing header must not match, got %q", got)
	}
}

func TestCompileRulesErrors(t *testing.T) {
	bad := []Rule{
		{Name: "a", Action: "nope"},
		{Name: "b", Action: ActionAllow, Match: Match{Paths: []string{"re:("}}},
		{Name: "c", Action: ActionAllow, Match: Match{IPs: []string{"not-an-ip"}}},
	}
	for _, r := range bad {
		if _, err := CompileRules([]Rule{r}); err == nil {
			t.Errorf("rule %s: expected error", r.Name)
		}
	}
}

func TestDefaultRulesCompile(t *testing.T) {
	rs := mustRules(t, DefaultRules()...)
	cases := []struct{ path, ua, want string }{
		{"/", "Mozilla/5.0 (compatible; Googlebot/2.1)", "Allow search engines"},
		{"/", "Mozilla/5.0 (compatible; ClaudeBot/1.0)", "Allow AI assistants"},
		{"/", "TelegramBot (like TwitterBot)", "Allow link previews"},
		{"/robots.txt", "anything", "Allow robots.txt and well-known files"},
		{"/page", "Mozilla/5.0 Firefox/130", "Check everyone else"},
		{"/", "curl/8", "Check everyone else"},
	}
	for _, c := range cases {
		if got := name(rs.Match(RuleRequest{Path: c.path, UserAgent: c.ua})); got != c.want {
			t.Errorf("%s %q: got %q, want %q", c.path, c.ua, got, c.want)
		}
	}
}
