package server

import (
	"net/netip"
	"sync"
	"time"
)

// usedSet remembers challenge randoms that were already redeemed, until the
// challenge would have expired anyway. Every entry costs the client a solved
// proof of work, which naturally bounds its growth; a hard cap protects
// against pathological configurations (difficulty 1).
type usedSet struct {
	mu        sync.Mutex
	m         map[string]int64 // random -> expiry (unix)
	lastSweep time.Time
}

const maxUsed = 1 << 20

func newUsedSet() *usedSet { return &usedSet{m: map[string]int64{}} }

// claim marks r as used. It reports false if r was already used.
func (u *usedSet) claim(r string, exp int64, now time.Time) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	if now.Sub(u.lastSweep) > time.Minute || len(u.m) >= maxUsed {
		u.sweep(now)
	}
	if _, ok := u.m[r]; ok {
		return false
	}
	if len(u.m) >= maxUsed {
		// Still full of live entries: refuse rather than grow without
		// bound or forget entries (which would allow replays).
		return false
	}
	u.m[r] = exp
	return true
}

func (u *usedSet) sweep(now time.Time) {
	t := now.Unix()
	for k, exp := range u.m {
		if exp <= t {
			delete(u.m, k)
		}
	}
	u.lastSweep = now
}

// failLimiter counts failed verifications per client network in fixed
// one-minute windows. Only clients that failed during the current minute are
// kept, and the map is capped.
type failLimiter struct {
	mu     sync.Mutex
	window int64 // current minute (unix / 60)
	m      map[netip.Addr]int
}

const maxFailEntries = 100_000

func newFailLimiter() *failLimiter { return &failLimiter{m: map[netip.Addr]int{}} }

// limiterKey groups IPv6 clients by /64, since a single host usually owns a
// whole /64 and could otherwise rotate addresses to evade the limit.
func limiterKey(ip netip.Addr) netip.Addr {
	ip = ip.Unmap()
	if ip.Is6() {
		if p, err := ip.Prefix(64); err == nil {
			return p.Addr()
		}
	}
	return ip
}

func (f *failLimiter) roll(now time.Time) {
	if w := now.Unix() / 60; w != f.window {
		f.window = w
		clear(f.m)
	}
}

// allowed reports whether ip may attempt another verification. max <= 0
// means unlimited.
func (f *failLimiter) allowed(ip netip.Addr, max int, now time.Time) bool {
	if max <= 0 {
		return true
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.roll(now)
	return f.m[limiterKey(ip)] < max
}

// fail records a failed attempt.
func (f *failLimiter) fail(ip netip.Addr, now time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.roll(now)
	k := limiterKey(ip)
	if _, ok := f.m[k]; !ok && len(f.m) >= maxFailEntries {
		return
	}
	f.m[k]++
}

// banList holds the clients the honeypot banned, by client network (IPv6 by
// /64, as in limiterKey), until their ban expires. It lives in memory: a
// restart lifts every ban.
type banList struct {
	mu        sync.Mutex
	m         map[netip.Addr]time.Time // client network -> end of the ban
	lastSweep time.Time
}

const maxBans = 100_000

func newBanList() *banList { return &banList{m: map[netip.Addr]time.Time{}} }

// banned reports whether ip is banned at now.
func (b *banList) banned(ip netip.Addr, now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	until, ok := b.m[limiterKey(ip)]
	return ok && now.Before(until)
}

// ban bans ip until until. A longer ban already in place is kept. When the
// list is full, expired bans are dropped first, then the bans ending soonest.
func (b *banList) ban(ip netip.Addr, until, now time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	k := limiterKey(ip)
	if cur, ok := b.m[k]; ok {
		if until.After(cur) {
			b.m[k] = until
		}
		return
	}
	if len(b.m) >= maxBans || now.Sub(b.lastSweep) > time.Hour {
		b.lastSweep = now
		for a, u := range b.m {
			if !now.Before(u) {
				delete(b.m, a)
			}
		}
		for len(b.m) >= maxBans {
			var first netip.Addr
			var end time.Time
			for a, u := range b.m {
				if end.IsZero() || u.Before(end) {
					first, end = a, u
				}
			}
			delete(b.m, first)
		}
	}
	b.m[k] = until
}
