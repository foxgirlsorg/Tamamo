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
