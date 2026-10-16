package config

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"strings"
)

// Pattern syntax (kept deliberately simple):
//   - plain text with optional * wildcards, e.g. /api/*  or  *GPTBot*
//   - "re:" prefix for a full Go regular expression, e.g. re:^/(a|b)/
//
// Paths and hosts must match the whole value. User agents and headers match
// anywhere ("contains"). Everything except paths ignores case, re: patterns
// included. A re: pattern is used as written: add ^ and $ to anchor it.

type matcher func(string) bool

func compilePattern(p string, anchored, fold bool) (matcher, error) {
	p = strings.TrimSpace(p)
	if strings.HasPrefix(p, "re:") {
		expr := strings.TrimPrefix(p, "re:")
		if fold {
			expr = "(?i)" + expr
		}
		re, err := regexp.Compile(expr)
		if err != nil {
			return nil, err
		}
		return re.MatchString, nil
	}
	expr := strings.ReplaceAll(regexp.QuoteMeta(p), `\*`, `.*`)
	if anchored {
		expr = "^" + expr + "$"
	}
	if fold {
		expr = "(?i)" + expr
	}
	re, err := regexp.Compile(expr)
	if err != nil {
		return nil, err
	}
	return re.MatchString, nil
}

func compileList(list []string, anchored, fold bool, what, rule string) ([]matcher, error) {
	var out []matcher
	for _, p := range list {
		if strings.TrimSpace(p) == "" {
			continue
		}
		m, err := compilePattern(p, anchored, fold)
		if err != nil {
			return nil, fmt.Errorf("rule %q: %s pattern %q: %v", rule, what, p, err)
		}
		out = append(out, m)
	}
	return out, nil
}

type compiledHeader struct {
	name string
	m    matcher
}

type compiledRule struct {
	rule    *Rule
	paths   []matcher
	uas     []matcher
	hosts   []matcher
	ips     []netip.Prefix
	methods map[string]bool
	headers []compiledHeader
}

// RuleSet is an ordered, compiled list of enabled rules. First match wins.
type RuleSet struct {
	rules []compiledRule
}

// RuleRequest is what rules are matched against.
type RuleRequest struct {
	Method    string
	Host      string
	Path      string
	UserAgent string
	IP        netip.Addr
	Header    http.Header
}

// CompileRules compiles every rule (disabled ones too, so errors surface early)
// and returns a set containing the enabled ones.
func CompileRules(rules []Rule) (*RuleSet, error) {
	rs := &RuleSet{}
	for i := range rules {
		r := &rules[i]
		name := r.Name
		if name == "" {
			name = fmt.Sprintf("#%d", i+1)
		}
		switch r.Action {
		case ActionAllow, ActionChallenge, ActionBlock:
		default:
			return nil, fmt.Errorf("rule %q: action must be allow, challenge or block", name)
		}
		cr := compiledRule{rule: r, methods: map[string]bool{}}
		var err error
		if cr.paths, err = compileList(r.Match.Paths, true, false, "path", name); err != nil {
			return nil, err
		}
		if cr.uas, err = compileList(r.Match.UserAgents, false, true, "user agent", name); err != nil {
			return nil, err
		}
		if cr.hosts, err = compileList(r.Match.Hosts, true, true, "host", name); err != nil {
			return nil, err
		}
		for _, ip := range r.Match.IPs {
			if strings.TrimSpace(ip) == "" {
				continue
			}
			p, err := ParsePrefix(ip)
			if err != nil {
				return nil, fmt.Errorf("rule %q: %q is not an IP or CIDR range", name, ip)
			}
			cr.ips = append(cr.ips, p)
		}
		for _, m := range r.Match.Methods {
			if m = strings.ToUpper(strings.TrimSpace(m)); m != "" {
				cr.methods[m] = true
			}
		}
		for _, h := range r.Match.Headers {
			if strings.TrimSpace(h.Name) == "" {
				continue
			}
			m, err := compilePattern(h.Pattern, false, true)
			if err != nil {
				return nil, fmt.Errorf("rule %q: header %s pattern: %v", name, h.Name, err)
			}
			cr.headers = append(cr.headers, compiledHeader{name: http.CanonicalHeaderKey(strings.TrimSpace(h.Name)), m: m})
		}
		if r.Enabled {
			rs.rules = append(rs.rules, cr)
		}
	}
	return rs, nil
}

func anyMatch(ms []matcher, v string) bool {
	for _, m := range ms {
		if m(v) {
			return true
		}
	}
	return false
}

// Every non-empty condition must hold; within one condition any entry may match.
// A rule with no conditions matches everything.
func (cr *compiledRule) matches(r RuleRequest) bool {
	if len(cr.paths) > 0 && !anyMatch(cr.paths, r.Path) {
		return false
	}
	if len(cr.uas) > 0 && !anyMatch(cr.uas, r.UserAgent) {
		return false
	}
	if len(cr.hosts) > 0 {
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		if !anyMatch(cr.hosts, host) {
			return false
		}
	}
	if len(cr.ips) > 0 {
		ok := false
		ip := r.IP.Unmap()
		for _, p := range cr.ips {
			if ip.IsValid() && p.Contains(ip) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if len(cr.methods) > 0 && !cr.methods[strings.ToUpper(r.Method)] {
		return false
	}
	for _, h := range cr.headers {
		vals := r.Header.Values(h.name)
		if len(vals) == 0 {
			return false
		}
		// Each value is matched on its own (any may match), so an anchored
		// pattern can't be dodged by sending the header twice.
		ok := false
		for _, v := range vals {
			if h.m(v) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

// Match returns the first enabled rule that matches, or nil.
func (s *RuleSet) Match(r RuleRequest) *Rule {
	if s == nil {
		return nil
	}
	for i := range s.rules {
		if s.rules[i].matches(r) {
			return s.rules[i].rule
		}
	}
	return nil
}
