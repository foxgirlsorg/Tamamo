package modules

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"net/http"
	"strings"
)

func init() {
	Register(Info{
		Name:        "bypass-header",
		Description: "Lets requests that carry a secret header through without a check, e.g. uptime monitors or your own scripts.",
		Settings: []SettingInfo{
			{Name: "header", Description: "Header name, e.g. X-Monitor-Token.", Required: true},
			{Name: "value", Description: "Secret value the header must have (at least 16 characters).", Required: true},
		},
	}, newBypassHeader)
}

type bypassHeader struct {
	header string
	sum    [32]byte
}

func newBypassHeader(s map[string]string) (Checker, error) {
	h := http.CanonicalHeaderKey(strings.TrimSpace(s["header"]))
	if h == "" || strings.ContainsAny(h, " \t\r\n:") {
		return nil, errors.New("setting \"header\" must be a header name like X-Monitor-Token")
	}
	v := s["value"]
	if len(v) < 16 {
		return nil, errors.New("setting \"value\" must be at least 16 characters long")
	}
	return &bypassHeader{header: h, sum: sha256.Sum256([]byte(v))}, nil
}

func (b *bypassHeader) Check(_ context.Context, r Request) (Decision, error) {
	match := 0
	for _, v := range r.Header.Values(b.header) {
		// Comparing hashes keeps the comparison constant-time regardless of
		// the length of what the client sent.
		got := sha256.Sum256([]byte(v))
		match |= subtle.ConstantTimeCompare(got[:], b.sum[:])
	}
	if match == 1 {
		return Decision{Action: Allow, Reason: "bypass header " + b.header}, nil
	}
	return Decision{}, nil
}
