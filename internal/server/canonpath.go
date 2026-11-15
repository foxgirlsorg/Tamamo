package server

import (
	"net/url"
	"path"
	"strings"
)

// canonicalPath splits a request URI (as sent by the client, or by nginx in
// X-Original-URI) into the path rules and modules match against and the raw
// query. The path is percent-decoded, repeated slashes are collapsed and
// "." / ".." segments are resolved, so "/public/../admin", "/%61dmin" and
// "//admin" all become "/admin" and can't slip past a rule for /admin. A
// trailing slash is kept. The upstream still receives the original path.
func canonicalPath(uri string) (p, query string) {
	p, query, _ = strings.Cut(uri, "?")
	p, _, _ = strings.Cut(p, "#")
	if dec, err := url.PathUnescape(p); err == nil {
		p = dec
	}
	if p == "" {
		return "/", query
	}
	trailing := strings.HasSuffix(p, "/")
	// path.Clean collapses repeated slashes and resolves dot segments; a
	// leading "/" makes ".." unable to climb above the root.
	p = path.Clean("/" + p)
	if trailing && p != "/" {
		p += "/"
	}
	return p, query
}

// CanonicalPath returns the path rules are matched against for a request URI
// (decoded, repeated slashes collapsed, . and .. resolved, query dropped).
// The admin rule tester uses it so it agrees with live traffic.
func CanonicalPath(uri string) string {
	p, _ := canonicalPath(uri)
	return p
}

// literalPath is the other way an upstream may read the path of uri: like
// canonicalPath, but "%2F", "%5C" and "%2E" stay as they are and "." / ".."
// segments are not resolved. Servers that route on the raw path (Node, Go and
// most application frameworks) see "/search/..%2Frobots.txt" as something
// under /search/, while canonicalPath (and nginx) see "/robots.txt".
func literalPath(uri string) string {
	p, _, _ := strings.Cut(uri, "?")
	p, _, _ = strings.Cut(p, "#")
	var b strings.Builder
	for i := 0; i < len(p); i++ {
		if p[i] == '%' && i+2 < len(p) {
			switch strings.ToLower(p[i+1 : i+3]) {
			case "2f", "5c", "2e":
				// Escape the escape, so unescaping below gives it back.
				b.WriteString("%25")
				continue
			}
		}
		b.WriteByte(p[i])
	}
	p = b.String()
	if dec, err := url.PathUnescape(p); err == nil {
		p = dec
	}
	if p == "" {
		return "/"
	}
	return p
}

// actionRank orders actions from most to least permissive.
func actionRank(action string) int {
	switch action {
	case "allow":
		return 0
	case "block":
		return 2
	}
	return 1
}
