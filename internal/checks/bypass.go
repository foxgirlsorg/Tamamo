package checks

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"net/http"
	"strings"
)

// MinBypassValue is the shortest secret a bypass header may have.
const MinBypassValue = 16

// Bypass lets requests that carry a secret header through without a check,
// e.g. uptime monitors or the site owner's own scripts.
type Bypass struct {
	Name   string
	header string
	sum    [32]byte
}

// CheckBypass validates a bypass header's name and secret value and returns
// the canonical header name.
func CheckBypass(header, value string) (string, error) {
	h := http.CanonicalHeaderKey(strings.TrimSpace(header))
	if h == "" || strings.ContainsAny(h, " \t\r\n:") {
		return "", errors.New("the header must be a header name like X-Monitor-Token")
	}
	if len(value) < MinBypassValue {
		return "", errors.New("the value must be at least 16 characters long")
	}
	return h, nil
}

// NewBypass creates a bypass check.
func NewBypass(name, header, value string) (*Bypass, error) {
	h, err := CheckBypass(header, value)
	if err != nil {
		return nil, err
	}
	return &Bypass{Name: name, header: h, sum: sha256.Sum256([]byte(value))}, nil
}

// Match reports whether the request header carries the secret.
func (b *Bypass) Match(h http.Header) bool {
	match := 0
	for _, v := range h.Values(b.header) {
		// Comparing hashes keeps the comparison constant-time regardless of
		// the length of what the client sent.
		got := sha256.Sum256([]byte(v))
		match |= subtle.ConstantTimeCompare(got[:], b.sum[:])
	}
	return match == 1
}
