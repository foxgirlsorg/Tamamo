package core

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// IP sources accepted by ClientIP.
const (
	SourceRemote        = "remote"
	SourceXForwardedFor = "x-forwarded-for"
	SourceXRealIP       = "x-real-ip"
	SourceCFConnecting  = "cf-connecting-ip"
)

// PeerAddr returns the address of the direct peer (r.RemoteAddr), unmapped.
// It returns the zero Addr when RemoteAddr cannot be parsed.
func PeerAddr(r *http.Request) netip.Addr {
	if ap, err := netip.ParseAddrPort(r.RemoteAddr); err == nil {
		return ap.Addr().Unmap().WithZone("")
	}
	host := r.RemoteAddr
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if a, err := netip.ParseAddr(host); err == nil {
		return a.Unmap().WithZone("")
	}
	return netip.Addr{}
}

func inPrefixes(a netip.Addr, list []netip.Prefix) bool {
	for _, p := range list {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// parseHeaderAddr parses a single address as found in a proxy header. It
// accepts bare addresses, "[v6]" and "addr:port" forms.
func parseHeaderAddr(s string) (netip.Addr, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return netip.Addr{}, false
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return a.Unmap().WithZone(""), true
	}
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.Addr().Unmap().WithZone(""), true
	}
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		if a, err := netip.ParseAddr(s[1 : len(s)-1]); err == nil {
			return a.Unmap().WithZone(""), true
		}
	}
	return netip.Addr{}, false
}

// PeerTrusted reports whether proxy headers on r are honored: a header IP
// source is configured and the direct peer is a trusted proxy (or the trusted
// list is empty). It is the same test ClientIP applies.
func PeerTrusted(r *http.Request, source string, trusted []netip.Prefix) bool {
	if source == "" || source == SourceRemote {
		return false
	}
	if len(trusted) == 0 {
		return true
	}
	peer := PeerAddr(r)
	return peer.IsValid() && inPrefixes(peer, trusted)
}

// ClientIP works out the visitor's address.
//
// source selects where to look: "remote" (the TCP peer), or one of the proxy
// headers "x-forwarded-for", "x-real-ip" and "cf-connecting-ip". A header is
// only honored when the direct peer is one of the trusted proxies, or when
// trusted is empty. An empty list means "trust any peer", which is only safe
// when Tamamo is not directly reachable from the internet (otherwise anyone
// can pick their own IP by sending the header).
//
// For X-Forwarded-For the list is walked from the right, skipping trusted
// proxies, and the first untrusted address is returned. With an empty
// trusted list the rightmost entry is used, since that is the one added by
// the proxy directly in front of Tamamo.
//
// When the header is missing, unparsable or not trusted, the direct peer's
// address is returned. The result is always unmapped (::ffff:1.2.3.4 becomes
// 1.2.3.4).
func ClientIP(r *http.Request, source string, trusted []netip.Prefix) netip.Addr {
	peer := PeerAddr(r)
	if source == "" || source == SourceRemote {
		return peer
	}
	if len(trusted) > 0 && (!peer.IsValid() || !inPrefixes(peer, trusted)) {
		return peer
	}
	switch source {
	case SourceXForwardedFor:
		// Multiple header lines are equivalent to one comma-joined line.
		var parts []string
		for _, line := range r.Header.Values("X-Forwarded-For") {
			parts = append(parts, strings.Split(line, ",")...)
		}
		var last netip.Addr
		for i := len(parts) - 1; i >= 0; i-- {
			a, ok := parseHeaderAddr(parts[i])
			if !ok {
				// Garbage in the chain: everything left of it is
				// untrustworthy. Use what we have so far.
				break
			}
			if len(trusted) == 0 || !inPrefixes(a, trusted) {
				return a
			}
			last = a
		}
		if last.IsValid() {
			// Every hop was a trusted proxy; the leftmost one is the
			// closest we can get to the client.
			return last
		}
	case SourceXRealIP:
		if a, ok := parseHeaderAddr(r.Header.Get("X-Real-IP")); ok {
			return a
		}
	case SourceCFConnecting:
		if a, ok := parseHeaderAddr(r.Header.Get("CF-Connecting-IP")); ok {
			return a
		}
	}
	return peer
}
