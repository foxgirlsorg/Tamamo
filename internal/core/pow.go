package core

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"strings"
)

// ChallengeClaims is the payload of a signed challenge token handed to the
// browser together with the challenge page.
type ChallengeClaims struct {
	R string `json:"r"` // random challenge string
	D int    `json:"d"` // difficulty: number of leading zero hex digits
	E int64  `json:"e"` // expiry, unix seconds
	B string `json:"b"` // client binding, see BindHash
	S string `json:"s"` // site ID the challenge was issued for
}

// PassClaims is the payload of the visitor pass cookie issued after a
// successful proof of work.
type PassClaims struct {
	D int    `json:"d"` // difficulty that was solved
	E int64  `json:"e"` // expiry, unix seconds
	I int64  `json:"i"` // issued at, unix seconds
	B string `json:"b"` // client binding, see BindHash
	S string `json:"s"` // site ID the pass is valid for
	// X marks a pass handed to the page's script for another site
	// (/.tamamo/api/pass). It is only accepted in the X-Tamamo-Pass header
	// of a site that trusts S, never as a cookie.
	X bool `json:"x,omitempty"`
}

// MaxDifficulty is the largest difficulty CheckPoW accepts (a SHA-256 hex
// digest is 64 characters long).
const MaxDifficulty = 64

// NewRandom returns 16 cryptographically random bytes, hex encoded.
func NewRandom() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("tamamo: crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(b)
}

// validNonce reports whether n is 1-16 ASCII digits.
func validNonce(n string) bool {
	if len(n) < 1 || len(n) > 16 {
		return false
	}
	for i := 0; i < len(n); i++ {
		if n[i] < '0' || n[i] > '9' {
			return false
		}
	}
	return true
}

// CheckPoW verifies a proof of work: hex(sha256(random + nonce)) must start
// with difficulty '0' characters. The nonce must be 1-16 decimal digits.
// The computed hash is returned even when the check fails (empty when the
// input is rejected before hashing).
func CheckPoW(random, nonce string, difficulty int) (hash string, ok bool) {
	if !validNonce(nonce) || difficulty < 0 || difficulty > MaxDifficulty {
		return "", false
	}
	sum := sha256.Sum256([]byte(random + nonce))
	hash = hex.EncodeToString(sum[:])
	return hash, strings.HasPrefix(hash, strings.Repeat("0", difficulty))
}

// BindHash ties a token to the client that requested it. The IP is masked
// to its /24 (IPv4) or /64 (IPv6) network so that ordinary address churn
// (privacy extensions, CGNAT pools) does not invalidate passes. The result
// is the first 16 hex chars of a SHA-256 over the bound values, or "-" when
// nothing is bound.
func BindHash(ip netip.Addr, ua string, bindIP, bindUA bool) string {
	if !bindIP && !bindUA {
		return "-"
	}
	var sb strings.Builder
	if bindIP {
		sb.WriteString("ip:")
		ip = ip.Unmap()
		bits := 64
		if ip.Is4() {
			bits = 24
		}
		if p, err := ip.Prefix(bits); err == nil {
			sb.WriteString(p.String())
		} else {
			sb.WriteString("invalid")
		}
		sb.WriteByte('\n')
	}
	if bindUA {
		sb.WriteString("ua:")
		sb.WriteString(ua)
	}
	sum := sha256.Sum256([]byte(sb.String()))
	return hex.EncodeToString(sum[:])[:16]
}
