package modules

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"
)

func init() {
	Register(Info{
		Name:        "ratelimit",
		Description: "Limits how many requests one IP address (or IPv6 /64 network) may make in a time window.",
		Settings: []SettingInfo{
			{Name: "requests", Description: "Requests allowed per window.", Default: "120"},
			{Name: "window_seconds", Description: "Length of the window in seconds.", Default: "60"},
			{Name: "action", Description: "What happens past the limit: block or challenge.", Default: "block"},
			{Name: "ipv6_prefix", Description: "IPv6 addresses are counted per network of this size (48-128).", Default: "64"},
			{Name: "max_ips", Description: "Most addresses tracked at once; bounds memory use.", Default: "100000"},
		},
	}, newRateLimit)
}

type rlBucket struct {
	start time.Time // start of the current window
	cur   int       // requests in the current window
	prev  int       // requests in the previous window
}

// rateLimit is a sliding-window counter per client network: the estimate is
// the current window's count plus the previous window's count weighted by
// how much of it still overlaps the sliding window.
type rateLimit struct {
	limit   int
	window  time.Duration
	action  string
	v6bits  int
	maxIPs  int
	now     func() time.Time
	mu      sync.Mutex
	buckets map[netip.Prefix]*rlBucket
}

func newRateLimit(s map[string]string) (Checker, error) {
	limit, err := IntSetting(s, "requests", 120, 1, 1_000_000)
	if err != nil {
		return nil, err
	}
	win, err := IntSetting(s, "window_seconds", 60, 1, 86400)
	if err != nil {
		return nil, err
	}
	bits, err := IntSetting(s, "ipv6_prefix", 64, 48, 128)
	if err != nil {
		return nil, err
	}
	maxIPs, err := IntSetting(s, "max_ips", 100000, 100, 10_000_000)
	if err != nil {
		return nil, err
	}
	action := strings.ToLower(strings.TrimSpace(s["action"]))
	if action == "" {
		action = Block
	}
	if action != Block && action != Challenge {
		return nil, fmt.Errorf("setting \"action\" must be block or challenge")
	}
	return &rateLimit{
		limit: limit, window: time.Duration(win) * time.Second, action: action,
		v6bits: bits, maxIPs: maxIPs, now: time.Now, buckets: map[netip.Prefix]*rlBucket{},
	}, nil
}

func (rl *rateLimit) key(ip netip.Addr) netip.Prefix {
	ip = ip.Unmap()
	bits := 32
	if ip.Is6() {
		bits = rl.v6bits
	}
	p, _ := ip.Prefix(bits)
	return p
}

func (rl *rateLimit) Check(_ context.Context, r Request) (Decision, error) {
	if !r.IP.IsValid() {
		return Decision{}, nil
	}
	k := rl.key(r.IP)
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
		return Decision{Action: rl.action, Reason: fmt.Sprintf("more than %d requests in %s", rl.limit, rl.window)}, nil
	}
	b.cur++
	return Decision{}, nil
}

// evict drops buckets that no longer matter; if the map is still full (many
// active addresses) it drops an arbitrary eighth of them, so memory stays
// bounded at the cost of forgetting some counts.
func (rl *rateLimit) evict(now time.Time) {
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
