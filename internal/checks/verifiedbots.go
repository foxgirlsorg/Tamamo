package checks

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// A bot is a well-known crawler that can be confirmed by reverse DNS: the
// name its address resolves to ends in one of the domains, and that name
// resolves back to the address. The operators document this themselves.
type bot struct {
	name    string
	agents  []string // lowercase fragments of the user agent
	domains []string
}

var knownBots = []bot{
	{"Googlebot", []string{"googlebot", "adsbot-google", "mediapartners-google", "google-inspectiontool", "googleother", "storebot-google"}, []string{"googlebot.com", "google.com"}},
	{"Bingbot", []string{"bingbot", "adidxbot", "msnbot"}, []string{"search.msn.com"}},
	{"Yandex", []string{"yandex.com/bots"}, []string{"yandex.ru", "yandex.net", "yandex.com"}},
	{"Baiduspider", []string{"baiduspider"}, []string{"baidu.com", "baidu.jp"}},
	{"Applebot", []string{"applebot"}, []string{"applebot.apple.com"}},
	{"PetalBot", []string{"petalbot"}, []string{"petalsearch.com"}},
	{"MojeekBot", []string{"mojeekbot"}, []string{"mojeek.com"}},
}

// VerifiedBotNames lists the crawlers the check knows.
func VerifiedBotNames() []string {
	out := make([]string, len(knownBots))
	for i, b := range knownBots {
		out[i] = b.name
	}
	return out
}

// ClaimedBot reports which known crawler a user agent says it is.
func ClaimedBot(userAgent string) (name string, ok bool) {
	ua := strings.ToLower(userAgent)
	for _, b := range knownBots {
		for _, a := range b.agents {
			if strings.Contains(ua, a) {
				return b.name, true
			}
		}
	}
	return "", false
}

// Resolver is the part of net.Resolver the verifier uses.
type Resolver interface {
	LookupAddr(ctx context.Context, addr string) ([]string, error)
	LookupHost(ctx context.Context, host string) ([]string, error)
}

// Bot verification limits.
const (
	botLookupTimeout = 2 * time.Second
	botCacheEntries  = 50000
	botTTLVerified   = 24 * time.Hour
	botTTLFake       = time.Hour
)

type botVerdict struct {
	ok  bool
	exp time.Time
}

// BotVerifier confirms crawlers by forward-confirmed reverse DNS and
// remembers the answers per address.
type BotVerifier struct {
	res Resolver
	now func() time.Time

	mu    sync.Mutex
	cache map[string]botVerdict
}

// NewBotVerifier creates a verifier; a nil resolver means the system's.
func NewBotVerifier(res Resolver) *BotVerifier {
	if res == nil {
		res = net.DefaultResolver
	}
	return &BotVerifier{res: res, now: time.Now, cache: map[string]botVerdict{}}
}

// Verify reports whether ip belongs to the crawler called name. An error
// means DNS could not answer in time; nothing is remembered then.
func (v *BotVerifier) Verify(ctx context.Context, name string, ip netip.Addr) (bool, error) {
	var b *bot
	for i := range knownBots {
		if knownBots[i].name == name {
			b = &knownBots[i]
		}
	}
	if b == nil || !ip.IsValid() {
		return false, nil
	}
	ip = ip.Unmap()
	key := name + "\x00" + ip.String()
	now := v.now()
	v.mu.Lock()
	c, hit := v.cache[key]
	v.mu.Unlock()
	if hit && now.Before(c.exp) {
		return c.ok, nil
	}

	ctx, cancel := context.WithTimeout(ctx, botLookupTimeout)
	defer cancel()
	ok, err := v.lookup(ctx, b, ip)
	if err != nil {
		return false, err
	}
	ttl := botTTLFake
	if ok {
		ttl = botTTLVerified
	}
	v.mu.Lock()
	if len(v.cache) >= botCacheEntries {
		for k, c := range v.cache {
			if !now.Before(c.exp) {
				delete(v.cache, k)
			}
		}
		for k := range v.cache { // still full: forget some
			if len(v.cache) < botCacheEntries*7/8 {
				break
			}
			delete(v.cache, k)
		}
	}
	v.cache[key] = botVerdict{ok: ok, exp: now.Add(ttl)}
	v.mu.Unlock()
	return ok, nil
}

func (v *BotVerifier) lookup(ctx context.Context, b *bot, ip netip.Addr) (bool, error) {
	names, err := v.res.LookupAddr(ctx, ip.String())
	if err != nil {
		// "No such name" is an answer: the address has no reverse record.
		if de, ok := err.(*net.DNSError); ok && de.IsNotFound {
			return false, nil
		}
		return false, err
	}
	for _, n := range names {
		n = strings.ToLower(strings.TrimSuffix(n, "."))
		if !hasDomain(n, b.domains) {
			continue
		}
		addrs, err := v.res.LookupHost(ctx, n)
		if err != nil {
			if de, ok := err.(*net.DNSError); ok && de.IsNotFound {
				continue
			}
			return false, err
		}
		for _, a := range addrs {
			if got, err := netip.ParseAddr(a); err == nil && got.Unmap() == ip {
				return true, nil
			}
		}
	}
	return false, nil
}

func hasDomain(name string, domains []string) bool {
	for _, d := range domains {
		if strings.HasSuffix(name, "."+d) {
			return true
		}
	}
	return false
}
