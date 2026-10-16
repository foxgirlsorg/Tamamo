package config

import (
	"net/http"
	"net/netip"
	"testing"
)

func fxCompile(t *testing.T, rules ...Rule) *RuleSet {
	t.Helper()
	for i := range rules {
		rules[i].Enabled = true
		if rules[i].Action == "" {
			rules[i].Action = ActionBlock
		}
	}
	rs, err := CompileRules(rules)
	if err != nil {
		t.Fatal(err)
	}
	return rs
}

func fxMatched(rs *RuleSet, r RuleRequest) string {
	if m := rs.Match(r); m != nil {
		return m.Name
	}
	return ""
}

func TestRemoteAddrRule(t *testing.T) {
	for _, tt := range []struct {
		name  string
		cidrs []string
		ip    string
		ok    bool
	}{
		{"match_ipv4", []string{"0.0.0.0/0"}, "1.1.1.1", true},
		{"match_ipv4_in_ipv6", []string{"0.0.0.0/0"}, "::ffff:1.1.1.1", true},
		{"match_ipv4_in_ipv6_hex", []string{"0.0.0.0/0"}, "::ffff:101:101", true},
		{"match_ipv6", []string{"::/0"}, "cafe:babe::", true},
		{"not_match_ipv4", []string{"1.1.1.1/32"}, "1.1.1.2", false},
		{"not_match_ipv6", []string{"cafe:babe::/128"}, "cafe:babe:4::", false},
		{"single address", []string{"203.0.113.7"}, "203.0.113.7", true},
		{"single address other", []string{"203.0.113.7"}, "203.0.113.8", false},
		{"mapped rule address", []string{"::ffff:203.0.113.7"}, "203.0.113.7", true},
		{"unmasked cidr", []string{"10.1.2.3/8"}, "10.200.0.1", true},
		{"no_ip_set", []string{"::/0"}, "", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			rs := fxCompile(t, Rule{Name: "ip", Match: Match{IPs: tt.cidrs}})
			var ip netip.Addr
			if tt.ip != "" {
				ip = netip.MustParseAddr(tt.ip)
			}
			if got := fxMatched(rs, RuleRequest{Method: "GET", Path: "/", IP: ip}) == "ip"; got != tt.ok {
				t.Errorf("match=%v, want %v", got, tt.ok)
			}
		})
	}
	for _, bad := range []string{"According to all natural laws of aviation", "10.0.0.0/33", "1.2.3", "::g"} {
		if _, err := CompileRules([]Rule{{Name: "ip", Enabled: true, Action: ActionBlock, Match: Match{IPs: []string{bad}}}}); err == nil {
			t.Errorf("invalid IP %q accepted", bad)
		}
	}
}

func TestHeaderMatchesRule(t *testing.T) {
	for _, tt := range []struct {
		name, header, pattern, key, value string
		ok                                bool
	}{
		{"match", "Cf-Worker", "re:.*", "Cf-Worker", "true", true},
		{"match wildcard", "cf-worker", "*", "Cf-Worker", "true", true},
		{"not_match", "Cf-Worker", "re:^false$", "Cf-Worker", "true", false},
		{"not_present", "Cf-Worker", "foobar", "Something-Else", "true", false},
		{"not_present wildcard", "Cf-Worker", "*", "Something-Else", "true", false},
		{"contains, case-insensitive", "Accept-Language", "*DE*", "Accept-Language", "en;q=0.5, de-DE", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			rs := fxCompile(t, Rule{Name: "h", Match: Match{Headers: []HeaderMatch{{Name: tt.header, Pattern: tt.pattern}}}})
			h := http.Header{}
			h.Set(tt.key, tt.value)
			if got := fxMatched(rs, RuleRequest{Method: "GET", Path: "/", Header: h}) == "h"; got != tt.ok {
				t.Errorf("match=%v, want %v", got, tt.ok)
			}
		})
	}
	if _, err := CompileRules([]Rule{{Name: "h", Enabled: true, Action: ActionBlock, Match: Match{Headers: []HeaderMatch{{Name: "X", Pattern: "re:a(b"}}}}}); err == nil {
		t.Error("invalid header regex accepted")
	}
}

func TestCloudflareWorkersRule(t *testing.T) {
	rs := fxCompile(t,
		Rule{Name: "cf-workers", Action: ActionBlock, Match: Match{Headers: []HeaderMatch{{Name: "Cf-Worker", Pattern: "*"}}}},
		Rule{Name: "allow", Action: ActionAllow},
	)
	h := http.Header{}
	h.Set("Cf-Worker", "true")
	if got := rs.Match(RuleRequest{Method: "GET", Path: "/", Header: h}); got == nil || got.Action != ActionBlock {
		t.Errorf("with Cf-Worker: %+v", got)
	}
	if got := rs.Match(RuleRequest{Method: "GET", Path: "/", Header: http.Header{}}); got == nil || got.Action != ActionAllow {
		t.Errorf("without Cf-Worker: %+v", got)
	}
}

func TestInvalidRulesRejected(t *testing.T) {
	for name, r := range map[string]Rule{
		"bad path regex":         {Match: Match{Paths: []string{"re:a(b"}}},
		"bad user agent":         {Match: Match{UserAgents: []string{"re:[unclosed"}}},
		"bad host regex":         {Match: Match{Hosts: []string{"re:*.example.com"}}},
		"bad header regex":       {Match: Match{Headers: []HeaderMatch{{Name: "X-Test", Pattern: "re:(?<x"}}}},
		"bad ip":                 {Match: Match{IPs: []string{"not-an-ip"}}},
		"bad cidr":               {Match: Match{IPs: []string{"192.0.2.0/99"}}},
		"uppercase action DENY":  {Action: "DENY"},
		"uppercase action WEIGH": {Action: "WEIGH"},
		"empty action":           {Action: ""},
	} {
		t.Run(name, func(t *testing.T) {
			r.Name = name
			r.Enabled = true
			if r.Action == "" && name != "empty action" {
				r.Action = ActionBlock
			}
			if _, err := CompileRules([]Rule{r}); err == nil {
				t.Error("CompileRules accepted it")
			}
			// Disabled rules are validated too.
			r.Enabled = false
			if _, err := CompileRules([]Rule{r}); err == nil {
				t.Error("CompileRules accepted it when disabled")
			}
			c := Defaults()
			c.Rules = []Rule{r}
			if err := c.Validate(); err == nil {
				t.Error("Validate accepted it")
			}
		})
	}
}

func TestFirstMatchWins(t *testing.T) {
	rs := fxCompile(t,
		Rule{Name: "allow-api-get", Action: ActionAllow, Match: Match{Paths: []string{"/api/*"}, Methods: []string{"get"}}},
		Rule{Name: "block-api", Action: ActionBlock, Match: Match{Paths: []string{"/api/*"}}},
		Rule{Name: "challenge-all", Action: ActionChallenge},
	)
	for _, tc := range []struct{ method, path, want string }{
		{"GET", "/api/x", "allow-api-get"},
		{"get", "/api/x", "allow-api-get"},
		{"POST", "/api/x", "block-api"},
		{"GET", "/", "challenge-all"},
	} {
		if got := fxMatched(rs, RuleRequest{Method: tc.method, Path: tc.path}); got != tc.want {
			t.Errorf("%s %s: %q, want %q", tc.method, tc.path, got, tc.want)
		}
	}
	disabled := []Rule{
		{Name: "off", Enabled: false, Action: ActionBlock},
		{Name: "on", Enabled: true, Action: ActionAllow},
	}
	rs2, err := CompileRules(disabled)
	if err != nil {
		t.Fatal(err)
	}
	if got := fxMatched(rs2, RuleRequest{Method: "GET", Path: "/"}); got != "on" {
		t.Errorf("disabled rule matched: %q", got)
	}
}

func TestPatternSemantics(t *testing.T) {
	rs := fxCompile(t,
		Rule{Name: "path", Match: Match{Paths: []string{"/admin"}}},
		Rule{Name: "ua", Match: Match{UserAgents: []string{"gptbot"}}},
		Rule{Name: "host", Match: Match{Hosts: []string{"*.example.com"}}},
		Rule{Name: "and", Match: Match{Paths: []string{"/both"}, UserAgents: []string{"curl"}}},
	)
	for _, tc := range []struct {
		r    RuleRequest
		want string
	}{
		{RuleRequest{Path: "/admin"}, "path"},
		{RuleRequest{Path: "/admin/x"}, ""},
		{RuleRequest{Path: "/x/admin"}, ""},
		{RuleRequest{Path: "/ADMIN"}, ""},
		{RuleRequest{Path: "/", UserAgent: "Mozilla/5.0 (compatible; GPTBot/1.2)"}, "ua"},
		{RuleRequest{Path: "/", Host: "shop.example.com"}, "host"},
		{RuleRequest{Path: "/", Host: "SHOP.Example.com:8443"}, "host"},
		{RuleRequest{Path: "/", Host: "example.com.evil.net"}, ""},
		{RuleRequest{Path: "/", Host: "evilexample.com"}, ""},
		{RuleRequest{Path: "/both", UserAgent: "curl/8"}, "and"},
		{RuleRequest{Path: "/both", UserAgent: "wget"}, ""},
		{RuleRequest{Path: "/other", UserAgent: "curl/8"}, ""},
	} {
		if got := fxMatched(rs, tc.r); got != tc.want {
			t.Errorf("%+v: %q, want %q", tc.r, got, tc.want)
		}
	}
	// Regex metacharacters in plain patterns are literal.
	rs = fxCompile(t, Rule{Name: "dot", Match: Match{Paths: []string{"/a.b"}}})
	if fxMatched(rs, RuleRequest{Path: "/axb"}) != "" || fxMatched(rs, RuleRequest{Path: "/a.b"}) != "dot" {
		t.Error("plain pattern treated '.' as a regex wildcard")
	}
}
