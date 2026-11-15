package checks

import (
	"net/netip"
	"sync"
	"time"
)

type rlBucket struct {
	start time.Time // start of the current window
	cur   int       // requests in the current window
	prev  int       // requests in the previous window
}

// RateLimit is a sliding-window counter per client network: the estimate is
// the current window's count plus the previous window's count weighted by
// how much of it still overlaps the sliding window.
type RateLimit struct {
	limit   int
	window  time.Duration
	v6bits  int
	maxIPs  int
	now     func() time.Time
	mu      sync.Mutex
	buckets map[netip.Prefix]*rlBucket
}

// NewRateLimit allows limit requests per window for each IPv4 address or
// IPv6 network of v6bits bits, tracking at most maxIPs of them.
func NewRateLimit(limit int, window time.Duration, v6bits, maxIPs int) *RateLimit {
	return &RateLimit{
		limit: max(limit, 1), window: max(window, time.Second), v6bits: min(max(v6bits, 1), 128),
		maxIPs: max(maxIPs, 1), now: time.Now, buckets: map[netip.Prefix]*rlBucket{},
	}
}

// SetClock replaces the time source (tests).
func (rl *RateLimit) SetClock(now func() time.Time) { rl.now = now }

func (rl *RateLimit) key(ip netip.Addr) netip.Prefix {
	ip = ip.Unmap()
	bits := 32
	if ip.Is6() {
		bits = rl.v6bits
	}
	p, _ := ip.Prefix(bits)
	return p
}

// Over counts a request from ip and reports whether it is past the limit.
// Requests past the limit are not counted, and unknown addresses never are.
func (rl *RateLimit) Over(ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}
	k := rl.key(ip)
	now := rl.now()

	rl.mu.Lock()
	defer rl.mu.Unlock()
	b := rl.buckets[k]
	if b == nil {
		if len(rl.buckets) >= rl.maxIPs {
			rl.evict(now)
		}
		b = &rlBucket{start: now}
		rl.buckets[k] = b
	}
	if el := now.Sub(b.start); el >= rl.window {
		n := int(el / rl.window)
		if n == 1 {
			b.prev = b.cur
		} else {
			b.prev = 0
		}
		b.cur = 0
		b.start = b.start.Add(time.Duration(n) * rl.window)
	}
	overlap := 1 - float64(now.Sub(b.start))/float64(rl.window)
	estimate := float64(b.prev)*overlap + float64(b.cur)
	if estimate >= float64(rl.limit) {
		return true
	}
	b.cur++
	return false
}

// evict drops buckets that no longer matter; if the map is still full (many
// active addresses) it drops an arbitrary eighth of them, so memory stays
// bounded at the cost of forgetting some counts.
func (rl *RateLimit) evict(now time.Time) {
	for k, b := range rl.buckets {
		if now.Sub(b.start) >= 2*rl.window {
			delete(rl.buckets, k)
		}
	}
	if len(rl.buckets) < rl.maxIPs {
		return
	}
	drop := rl.maxIPs/8 + 1
	for k := range rl.buckets { // map order is random
		delete(rl.buckets, k)
		if drop--; drop == 0 {
			break
		}
	}
}
