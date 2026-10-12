// Package core holds Tamamo's security primitives: signed tokens, the
// proof-of-work check, client binding and client-IP resolution.
package core

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
)

// ErrBadToken is returned for any malformed or forged token. Callers should
// not distinguish between the two, so a single error is used.
var ErrBadToken = errors.New("invalid token")

var b64 = base64.RawURLEncoding

// Signer creates and checks HMAC-SHA256 signed JSON tokens.
//
// Every signer derives its own key from the shared secret and a purpose
// string, so a token minted for one purpose (say, a challenge) can never be
// presented as another (say, a visitor pass).
type Signer struct {
	key []byte
}

// NewSigner returns a signer whose key is HMAC-SHA256(secret, purpose).
func NewSigner(secret, purpose string) *Signer {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(purpose))
	return &Signer{key: m.Sum(nil)}
}

func (s *Signer) mac(payload string) []byte {
	m := hmac.New(sha256.New, s.key)
	m.Write([]byte(payload))
	return m.Sum(nil)
}

// Sign encodes v as JSON and returns base64url(json) + "." + base64url(mac).
// It returns "" only if v cannot be encoded as JSON, which is a programming
// error for the claim types used by Tamamo.
func (s *Signer) Sign(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	payload := b64.EncodeToString(b)
	return payload + "." + b64.EncodeToString(s.mac(payload))
}

// Verify checks the token's signature in constant time and, if it is valid,
// decodes the payload into v. It does not check any expiry: that is up to
// the caller, which knows the claim type.
func (s *Signer) Verify(tok string, v any) error {
	payload, sig, ok := strings.Cut(tok, ".")
	if !ok || payload == "" || sig == "" || len(tok) > 4096 {
		return ErrBadToken
	}
	got, err := b64.DecodeString(sig)
	if err != nil {
		return ErrBadToken
	}
	if !hmac.Equal(got, s.mac(payload)) {
		return ErrBadToken
	}
	b, err := b64.DecodeString(payload)
	if err != nil {
		return ErrBadToken
	}
	if err := json.Unmarshal(b, v); err != nil {
		return ErrBadToken
	}
	return nil
}
