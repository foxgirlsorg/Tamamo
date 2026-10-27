package config

import (
	"fmt"
	"net"
	"regexp"
	"strings"
)

var adminDomain = regexp.MustCompile(`^(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// NormalizeAdminDomains lowercases and checks the admin API's host names:
// plain names ("admin.example.com") or one leading wildcard ("*.example.com"),
// without schemes, ports or paths. Empty entries are dropped.
func NormalizeAdminDomains(in []string) ([]string, error) {
	out := []string{}
	seen := map[string]bool{}
	for _, d := range in {
		d = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".")
		if d == "" {
			continue
		}
		switch {
		case strings.Contains(d, "://"):
			return nil, fmt.Errorf("admin domain %q: leave out the scheme, e.g. admin.example.com", d)
		case strings.ContainsAny(d, ":/"):
			return nil, fmt.Errorf("admin domain %q: only the host name, without a port or path", d)
		case len(d) > 253 || !adminDomain.MatchString(d):
			return nil, fmt.Errorf("admin domain %q is not a host name like admin.example.com or *.example.com", d)
		}
		if !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
	}
	return out, nil
}

// AdminHostAllowed reports whether a request's Host header (port ignored) is
// one of domains. "*.example.com" matches any subdomain of example.com, not
// example.com itself. An empty list allows every host.
func AdminHostAllowed(domains []string, host string) bool {
	if len(domains) == 0 {
		return true
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if host == "" {
		return false
	}
	for _, d := range domains {
		if suffix, ok := strings.CutPrefix(d, "*"); ok {
			if strings.HasSuffix(host, suffix) && len(host) > len(suffix) {
				return true
			}
		} else if host == d {
			return true
		}
	}
	return false
}
