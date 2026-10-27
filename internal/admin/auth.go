package admin

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// pbkdf2Iterations is the work factor for new password hashes. Tests lower it.
var pbkdf2Iterations = 600_000

const (
	sessionCookie = "tamamo_admin"
	minUsername   = 3
	maxUsername   = 64
	minPassword   = 8
	maxPassword   = 1024
)

// hashPassword returns "pbkdf2-sha256$<iter>$<salthex>$<hashhex>".
func hashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key, err := pbkdf2.Key(sha256.New, password, salt, pbkdf2Iterations, 32)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("pbkdf2-sha256$%d$%s$%s", pbkdf2Iterations, hex.EncodeToString(salt), hex.EncodeToString(key)), nil
}

// dummyHash is verified against when the username is wrong, so both failure
// paths cost the same time.
var (
	dummyOnce sync.Once
	dummyHash string
)

func getDummyHash() string {
	dummyOnce.Do(func() {
		dummyHash, _ = hashPassword("tamamo-dummy-password")
	})
	return dummyHash
}

// verifyPassword checks password against an encoded hash in constant time.
func verifyPassword(encoded, password string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2-sha256" {
		return false
	}
	iter, err := strconv.Atoi(parts[1])
	if err != nil || iter < 1 || iter > 10_000_000 {
		return false
	}
	salt, err := hex.DecodeString(parts[2])
	if err != nil {
		return false
	}
	want, err := hex.DecodeString(parts[3])
	if err != nil || len(want) == 0 {
		return false
	}
	got, err := pbkdf2.Key(sha256.New, password, salt, iter, len(want))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(got, want) == 1
}

// HashPassword, VerifyPassword and ValidateCredentials let the command line
// set the admin login without the web UI.
func HashPassword(password string) (string, error) { return hashPassword(password) }
func VerifyPassword(encoded, password string) bool { return verifyPassword(encoded, password) }
func ValidateCredentials(username, password string) error {
	return validateCredentials(username, password)
}

func validateCredentials(username, password string) error {
	if n := len([]rune(username)); n < minUsername || n > maxUsername {
		return fmt.Errorf("the username must be %d to %d characters long", minUsername, maxUsername)
	}
	if strings.TrimSpace(username) != username {
		return errors.New("the username can't start or end with a space")
	}
	if len([]rune(password)) < minPassword {
		return fmt.Errorf("the password must be at least %d characters long", minPassword)
	}
	if len(password) > maxPassword {
		return errors.New("the password is too long")
	}
	return nil
}

// ---- sessions ---------------------------------------------------------------

type session struct {
	username string
	expires  time.Time
}

type sessions struct {
	mu sync.Mutex
	m  map[string]*session
}

func newSessions() *sessions { return &sessions{m: map[string]*session{}} }

func (s *sessions) create(username string, ttl time.Duration) string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	tok := hex.EncodeToString(b)
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range s.m {
		if now.After(v.expires) {
			delete(s.m, k)
		}
	}
	s.m[tok] = &session{username: username, expires: now.Add(ttl)}
	return tok
}

func (s *sessions) get(tok string) (*session, bool) {
	if tok == "" {
		return nil, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.m[tok]
	if !ok {
		return nil, false
	}
	if time.Now().After(v.expires) {
		delete(s.m, tok)
		return nil, false
	}
	cp := *v
	return &cp, true
}

func (s *sessions) delete(tok string) {
	s.mu.Lock()
	delete(s.m, tok)
	s.mu.Unlock()
}

// keepOnly drops every session except tok and renames the remaining one.
func (s *sessions) keepOnly(tok, username string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range s.m {
		if k != tok {
			delete(s.m, k)
		} else {
			v.username = username
		}
	}
}

func (s *sessions) clear() {
	s.mu.Lock()
	s.m = map[string]*session{}
	s.mu.Unlock()
}

// ---- brute-force protection ------------------------------------------------

const (
	freeFailures = 5
	firstLockout = 30 * time.Second
	maxLockout   = 15 * time.Minute
	limiterMax   = 10_000
)

type attempt struct {
	failures int
	lockout  time.Duration
	until    time.Time
	last     time.Time
}

type limiter struct {
	mu  sync.Mutex
	m   map[string]*attempt
	now func() time.Time
}

func newLimiter() *limiter { return &limiter{m: map[string]*attempt{}, now: time.Now} }

// blocked reports how long ip must still wait before trying again.
func (l *limiter) blocked(ip string) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	a, ok := l.m[ip]
	if !ok {
		return 0
	}
	if d := a.until.Sub(l.now()); d > 0 {
		return d
	}
	return 0
}

func (l *limiter) fail(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if len(l.m) >= limiterMax {
		for k, v := range l.m {
			if now.Sub(v.last) > maxLockout*2 {
				delete(l.m, k)
			}
		}
	}
	a, ok := l.m[ip]
	if !ok {
		a = &attempt{}
		l.m[ip] = a
	}
	// Forget old history after a long quiet period.
	if !a.last.IsZero() && now.Sub(a.last) > maxLockout*2 {
		*a = attempt{}
	}
	a.failures++
	a.last = now
	if a.failures >= freeFailures {
		if a.lockout == 0 {
			a.lockout = firstLockout
		} else {
			a.lockout *= 2
			if a.lockout > maxLockout {
				a.lockout = maxLockout
			}
		}
		a.until = now.Add(a.lockout)
	}
}

func (l *limiter) succeed(ip string) {
	l.mu.Lock()
	delete(l.m, ip)
	l.mu.Unlock()
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func isHTTPS(r *http.Request) bool {
	return r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

func setSessionCookie(w http.ResponseWriter, r *http.Request, tok string, ttl time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    tok,
		Path:     "/",
		MaxAge:   int(ttl / time.Second),
		HttpOnly: true,
		Secure:   isHTTPS(r),
		SameSite: http.SameSiteStrictMode,
	})
}

func clearSessionCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   isHTTPS(r),
		SameSite: http.SameSiteStrictMode,
	})
}
