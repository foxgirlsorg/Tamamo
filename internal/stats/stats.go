// Package stats keeps Tamamo's traffic counters, hourly history, top lists
// and a ring buffer of recent events, for all sites combined and per site.
//
// The state is aggregated in memory and persisted to the SQLite database
// dataDir/tamamo.db (pure Go driver, no cgo): every 30 seconds while it has
// changed, on Run's shutdown and on Close.
package stats

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/foxgirlsorg/tamamo/internal/config"
)

// Event kinds.
const (
	KindPass      = "pass"      // valid pass cookie, proxied
	KindAllow     = "allow"     // allowed by a rule or the default, proxied
	KindChallenge = "challenge" // challenge page served
	KindBlock     = "block"     // denied page served
	KindSolve     = "solve"     // proof of work accepted
	KindFail      = "fail"      // proof of work rejected
)

const (
	keepHours   = 8 * 24 // hourly buckets kept (enough for the 7-day view)
	maxTopItems = 1000   // cap for each top-N map
	maxSites    = 200    // cap for per-site statistics
	topN        = 10
	maxUA       = 300
	maxPath     = 500
	saveEvery   = 30 * time.Second
)

// Counters are cumulative per-kind counts. Requests counts proxied, blocked
// and challenged requests (not verify calls).
type Counters struct {
	Requests   int64 `json:"requests"`
	Passed     int64 `json:"passed"`
	Allowed    int64 `json:"allowed"`
	Challenged int64 `json:"challenged"`
	Solved     int64 `json:"solved"`
	Failed     int64 `json:"failed"`
	Blocked    int64 `json:"blocked"`
}

func (c *Counters) add(o Counters) {
	c.Requests += o.Requests
	c.Passed += o.Passed
	c.Allowed += o.Allowed
	c.Challenged += o.Challenged
	c.Solved += o.Solved
	c.Failed += o.Failed
	c.Blocked += o.Blocked
}

// count bumps the counters for one event kind. It reports false for unknown kinds.
func (c *Counters) count(kind string) bool {
	switch kind {
	case KindPass:
		c.Requests++
		c.Passed++
	case KindAllow:
		c.Requests++
		c.Allowed++
	case KindChallenge:
		c.Requests++
		c.Challenged++
	case KindBlock:
		c.Requests++
		c.Blocked++
	case KindSolve:
		c.Solved++
	case KindFail:
		c.Failed++
	default:
		return false
	}
	return true
}

// Event is one recorded request or verification.
type Event struct {
	Time    time.Time `json:"time"`
	Kind    string    `json:"kind"`
	Site    string    `json:"site"` // site ID
	IP      string    `json:"ip"`
	Host    string    `json:"host"`
	Path    string    `json:"path"`
	UA      string    `json:"ua"`
	Rule    string    `json:"rule"`
	SolveMs int64     `json:"solve_ms,omitempty"`
}

// HourBucket holds the counters of one hour (or day) starting at T (unix seconds).
type HourBucket struct {
	T int64 `json:"t"`
	Counters
}

// Named is an entry of a top-N list.
type Named struct {
	Name  string `json:"name"`
	Count int64  `json:"count"`
}

// SiteCounters summarizes one site in the all-sites snapshot.
type SiteCounters struct {
	Site    string   `json:"site"`
	Last24h Counters `json:"last24h"`
}

// Snapshot is a point-in-time copy of the statistics, shaped for the web UI.
type Snapshot struct {
	Since         time.Time      `json:"since"`
	UptimeSeconds int64          `json:"uptime_seconds"`
	Enabled       bool           `json:"enabled"`
	Totals        Counters       `json:"totals"`
	Last24h       Counters       `json:"last24h"`
	Hours         []HourBucket   `json:"hours"` // 24, oldest first, last = current hour
	Days          []HourBucket   `json:"days"`  // 7, oldest first, UTC days
	AvgSolveMs    float64        `json:"avg_solve_ms"`
	TopRules      []Named        `json:"top_rules"`
	TopUserAgents []Named        `json:"top_user_agents"`
	TopPaths      []Named        `json:"top_paths"`
	TopIPs        []Named        `json:"top_ips"`
	Events        []Event        `json:"events"` // newest first
	Sites         []SiteCounters `json:"sites"`  // only in the all-sites snapshot
}

// bucket is the full set of statistics for one scope (all sites, or one site).
type bucket struct {
	Totals     Counters            `json:"totals"`
	Hours      map[int64]*Counters `json:"-"` // hour start (unix) -> counters
	SolveSum   int64               `json:"solve_sum_ms"`
	SolveCount int64               `json:"solve_count"`
	Rules      map[string]int64    `json:"rules"`
	UAs        map[string]int64    `json:"user_agents"`
	Paths      map[string]int64    `json:"paths"`
	IPs        map[string]int64    `json:"ips"`
}

func newBucket() *bucket {
	return &bucket{
		Hours: map[int64]*Counters{},
		Rules: map[string]int64{},
		UAs:   map[string]int64{},
		Paths: map[string]int64{},
		IPs:   map[string]int64{},
	}
}

// persistedBucket is a bucket with its hours as a sorted list.
type persistedBucket struct {
	bucket
	HourList []HourBucket `json:"hours"`
}

func (b *bucket) persist() persistedBucket {
	p := persistedBucket{bucket: bucket{
		Totals: b.Totals, SolveSum: b.SolveSum, SolveCount: b.SolveCount,
		Rules: cloneMap(b.Rules), UAs: cloneMap(b.UAs), Paths: cloneMap(b.Paths), IPs: cloneMap(b.IPs),
	}}
	for t, c := range b.Hours {
		p.HourList = append(p.HourList, HourBucket{T: t, Counters: *c})
	}
	sort.Slice(p.HourList, func(i, j int) bool { return p.HourList[i].T < p.HourList[j].T })
	return p
}

func (p *persistedBucket) restore(now time.Time) *bucket {
	b := newBucket()
	b.Totals, b.SolveSum, b.SolveCount = p.Totals, p.SolveSum, p.SolveCount
	for _, h := range p.HourList {
		c := h.Counters
		b.Hours[h.T] = &c
	}
	b.pruneHours(now)
	for _, pair := range []struct{ dst, src map[string]int64 }{
		{b.Rules, p.Rules}, {b.UAs, p.UAs}, {b.Paths, p.Paths}, {b.IPs, p.IPs},
	} {
		for k, v := range pair.src {
			pair.dst[k] = v
		}
		capMap(pair.dst)
	}
	return b
}

func (b *bucket) record(e *Event, one Counters, storeIPs bool, now time.Time) {
	b.Totals.add(one)
	h := hourStart(e.Time)
	c := b.Hours[h]
	if c == nil {
		c = &Counters{}
		b.Hours[h] = c
		b.pruneHours(now)
	}
	c.add(one)
	if e.Kind == KindSolve {
		b.SolveSum += e.SolveMs
		b.SolveCount++
	}
	bump(b.Rules, e.Rule)
	switch e.Kind {
	case KindChallenge, KindBlock, KindFail:
		bump(b.UAs, e.UA)
		bump(b.Paths, e.Path)
		if storeIPs {
			bump(b.IPs, e.IP)
		}
	}
}

func (b *bucket) pruneHours(now time.Time) {
	cutoff := hourStart(now) - keepHours*3600
	for t := range b.Hours {
		if t <= cutoff {
			delete(b.Hours, t)
		}
	}
}

// last24h sums the 24 hourly buckets ending with the current hour.
func (b *bucket) last24h(now time.Time) Counters {
	var c Counters
	cur := hourStart(now)
	for t, h := range b.Hours {
		if t > cur-24*3600 && t <= cur {
			c.add(*h)
		}
	}
	return c
}

// Stats is safe for concurrent use.
type Stats struct {
	path    string // dataDir/tamamo.db
	db      *sql.DB
	mgr     *config.Manager
	started time.Time
	now     func() time.Time // replaceable in tests

	saveMu sync.Mutex // serializes database writes and guards db's closing

	mu       sync.Mutex
	since    time.Time
	all      *bucket
	sites    map[string]*bucket // site ID -> statistics, at most maxSites
	ring     []Event            // fixed-size ring of recent events
	ringNext int                // index of the next write
	ringLen  int                // number of valid entries
	dirty    bool
}

// persisted is the in-memory image of the saved state. The database is
// written and read through writeDB and readDB.
type persisted struct {
	Since  time.Time                  `json:"since"`
	All    persistedBucket            `json:"all"`
	Sites  map[string]persistedBucket `json:"sites"`
	Events []Event                    `json:"events"` // newest first
}

// New opens (creating if needed) dataDir/tamamo.db and loads the saved state.
// A corrupt database is moved aside and a fresh one started. Only a path
// that cannot be opened is an error.
func New(dataDir string, mgr *config.Manager) (*Stats, error) {
	s := &Stats{
		path:    filepath.Join(dataDir, dbFile),
		mgr:     mgr,
		started: time.Now(),
		now:     time.Now,
	}
	s.clear(s.started)

	db, err := openDB(s.path)
	if isCorrupt(err) {
		slog.Warn("stats database is corrupt, starting fresh", "path", s.path, "err", err)
		setAside(s.path)
		db, err = openDB(s.path)
	}
	if err != nil {
		return nil, fmt.Errorf("opening stats database %s: %w", s.path, err)
	}
	s.db = db

	has, err := hasData(db)
	switch {
	case err != nil:
		slog.Warn("reading stats database failed, starting fresh", "path", s.path, "err", err)
	case has:
		p, err := readDB(db)
		if err != nil {
			slog.Warn("stats database is unreadable, starting fresh", "path", s.path, "err", err)
		} else {
			s.load(p)
		}
	}
	return s, nil
}

func (s *Stats) clear(now time.Time) {
	s.since = now.UTC()
	s.all = newBucket()
	s.sites = map[string]*bucket{}
	s.ring = make([]Event, s.ringCap())
	s.ringNext, s.ringLen = 0, 0
}

func (s *Stats) load(p *persisted) {
	now := s.now()
	if !p.Since.IsZero() {
		s.since = p.Since
	}
	s.all = p.All.restore(now)
	for id, pb := range p.Sites {
		if len(s.sites) >= maxSites {
			break
		}
		s.sites[id] = pb.restore(now)
	}
	// Events are stored newest first; replay oldest first.
	for i := len(p.Events) - 1; i >= 0; i-- {
		s.push(p.Events[i])
	}
}

func (s *Stats) settings() config.StatsConfig {
	if s.mgr == nil {
		return config.Defaults().Stats
	}
	return s.mgr.Get().Stats
}

func (s *Stats) ringCap() int {
	n := s.settings().RecentEvents
	if n < 1 {
		n = 1
	}
	return n
}

// events returns the ring's contents, oldest first.
func (s *Stats) events() []Event {
	out := make([]Event, 0, s.ringLen)
	start := s.ringNext - s.ringLen
	if start < 0 {
		start += len(s.ring)
	}
	for i := 0; i < s.ringLen; i++ {
		out = append(out, s.ring[(start+i)%len(s.ring)])
	}
	return out
}

// push appends to the ring, resizing it first if the configured size changed.
func (s *Stats) push(e Event) {
	if c := s.ringCap(); c != len(s.ring) {
		old := s.events()
		if len(old) > c {
			old = old[len(old)-c:]
		}
		s.ring = make([]Event, c)
		copy(s.ring, old)
		s.ringLen = len(old)
		s.ringNext = len(old) % c
	}
	s.ring[s.ringNext] = e
	s.ringNext = (s.ringNext + 1) % len(s.ring)
	if s.ringLen < len(s.ring) {
		s.ringLen++
	}
}

// capMap keeps a top-N map bounded: once it exceeds maxTopItems entries the
// lower half (by count) is dropped.
func capMap(m map[string]int64) {
	if len(m) <= maxTopItems {
		return
	}
	list := sortedNamed(m)
	for _, n := range list[maxTopItems/2:] {
		delete(m, n.Name)
	}
}

func sortedNamed(m map[string]int64) []Named {
	list := make([]Named, 0, len(m))
	for k, v := range m {
		list = append(list, Named{Name: k, Count: v})
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].Count != list[j].Count {
			return list[i].Count > list[j].Count
		}
		return list[i].Name < list[j].Name
	})
	return list
}

func top(m map[string]int64) []Named {
	list := sortedNamed(m)
	if len(list) > topN {
		list = list[:topN]
	}
	return list
}

func bump(m map[string]int64, key string) {
	if key == "" {
		return
	}
	m[key]++
	capMap(m)
}

func hourStart(t time.Time) int64 { return t.Unix() - t.Unix()%3600 }

// truncate shortens s to at most n bytes without splitting a UTF-8 sequence.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && s[n]&0xC0 == 0x80 {
		n--
	}
	return s[:n]
}

// Record counts an event. Unknown kinds are ignored, as is everything while
// statistics are disabled in the config.
func (s *Stats) Record(e Event) {
	set := s.settings()
	if !set.Enabled {
		return
	}
	if e.Time.IsZero() {
		e.Time = s.now()
	}
	e.Time = e.Time.UTC()
	e.UA = truncate(e.UA, maxUA)
	e.Path = truncate(e.Path, maxPath)
	e.Site = truncate(e.Site, 64)
	if !set.StoreIPs {
		e.IP = ""
	}
	var one Counters
	if !one.count(e.Kind) {
		return
	}
	now := s.now()

	s.mu.Lock()
	defer s.mu.Unlock()
	s.dirty = true
	s.all.record(&e, one, set.StoreIPs, now)
	if e.Site != "" {
		b := s.sites[e.Site]
		if b == nil && len(s.sites) < maxSites {
			b = newBucket()
			s.sites[e.Site] = b
		}
		if b != nil {
			b.record(&e, one, set.StoreIPs, now)
		}
	}
	switch e.Kind {
	case KindChallenge, KindSolve, KindFail, KindBlock:
		s.push(e)
	}
}

// Snapshot returns a copy of the statistics of one site (by ID), or of all
// sites combined when site is "".
func (s *Stats) Snapshot(site string) Snapshot {
	set := s.settings()
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()

	b := s.all
	if site != "" {
		if b = s.sites[site]; b == nil {
			b = newBucket()
		}
	}
	snap := Snapshot{
		Since:         s.since,
		UptimeSeconds: int64(time.Since(s.started).Seconds()),
		Enabled:       set.Enabled,
		Totals:        b.Totals,
		TopRules:      top(b.Rules),
		TopUserAgents: top(b.UAs),
		TopPaths:      top(b.Paths),
		TopIPs:        top(b.IPs),
		Sites:         []SiteCounters{},
	}
	if !set.StoreIPs {
		snap.TopIPs = []Named{}
	}
	if b.SolveCount > 0 {
		snap.AvgSolveMs = float64(b.SolveSum) / float64(b.SolveCount)
	}

	cur := hourStart(now)
	snap.Hours = make([]HourBucket, 24)
	for i := range snap.Hours {
		t := cur - int64(23-i)*3600
		snap.Hours[i].T = t
		if c := b.Hours[t]; c != nil {
			snap.Hours[i].Counters = *c
			snap.Last24h.add(*c)
		}
	}

	today := now.UTC().Truncate(24 * time.Hour).Unix()
	first := today - 6*86400
	snap.Days = make([]HourBucket, 7)
	for i := range snap.Days {
		snap.Days[i].T = first + int64(i)*86400
	}
	for t, c := range b.Hours {
		if t < first {
			continue
		}
		if i := (t - first) / 86400; i < 7 {
			snap.Days[i].Counters.add(*c)
		}
	}

	ev := s.events()
	snap.Events = make([]Event, 0, len(ev))
	for i := len(ev) - 1; i >= 0; i-- {
		if site == "" || ev[i].Site == site {
			snap.Events = append(snap.Events, ev[i])
		}
	}

	if site == "" {
		for id, sb := range s.sites {
			snap.Sites = append(snap.Sites, SiteCounters{Site: id, Last24h: sb.last24h(now)})
		}
		sort.Slice(snap.Sites, func(i, j int) bool { return snap.Sites[i].Site < snap.Sites[j].Site })
	}
	return snap
}

// Reset clears every counter, list and event and saves the empty state.
func (s *Stats) Reset() {
	s.mu.Lock()
	s.clear(s.now())
	s.dirty = true
	s.mu.Unlock()
	if err := s.Save(); err != nil {
		slog.Warn("saving stats after reset failed", "err", err)
	}
}

// Save writes the whole statistics state to the database in one transaction.
func (s *Stats) Save() error {
	s.saveMu.Lock()
	defer s.saveMu.Unlock()
	if s.db == nil {
		return errClosed
	}

	s.mu.Lock()
	p := persisted{
		Since: s.since,
		All:   s.all.persist(),
		Sites: make(map[string]persistedBucket, len(s.sites)),
	}
	for id, b := range s.sites {
		p.Sites[id] = b.persist()
	}
	ev := s.events()
	p.Events = make([]Event, len(ev))
	for i, e := range ev {
		p.Events[len(ev)-1-i] = e
	}
	s.dirty = false
	s.mu.Unlock()

	err := writeDB(s.db, &p)
	if err != nil {
		s.mu.Lock()
		s.dirty = true
		s.mu.Unlock()
	}
	return err
}

// Close saves the statistics and closes the database. Calling it again is a
// no-op. The Stats must not be used for saving afterwards.
func (s *Stats) Close() error {
	err := s.Save()
	if errors.Is(err, errClosed) {
		return nil
	}
	s.saveMu.Lock()
	defer s.saveMu.Unlock()
	cerr := s.db.Close()
	s.db = nil
	if err != nil {
		return err
	}
	return cerr
}

// RenameSites moves the statistics of sites from old IDs to new IDs: m maps
// old ID to new ID. If the new ID already has statistics they are merged into
// it. Recent events are relabelled too. The change is saved on the next save.
func (s *Stats) RenameSites(m map[string]string) {
	olds := make([]string, 0, len(m))
	for old, nw := range m {
		if old != "" && nw != "" && old != nw {
			olds = append(olds, old)
		}
	}
	sort.Strings(olds)

	s.mu.Lock()
	defer s.mu.Unlock()

	// Detach every source first so chained renames (a->b, b->c) are safe.
	type move struct {
		to string
		b  *bucket
	}
	var moves []move
	for _, old := range olds {
		if b := s.sites[old]; b != nil {
			delete(s.sites, old)
			moves = append(moves, move{m[old], b})
		}
	}
	for _, mv := range moves {
		dst := s.sites[mv.to]
		switch {
		case dst != nil:
			dst.merge(mv.b)
		case len(s.sites) < maxSites:
			s.sites[mv.to] = mv.b
		}
		// Otherwise the site cap is full and the data is dropped, as in Record.
	}

	for i := range s.ring {
		if to, ok := m[s.ring[i].Site]; ok && s.ring[i].Site != "" && to != "" {
			s.ring[i].Site = to
		}
	}
	s.dirty = true
}

// merge adds the statistics of o into b.
func (b *bucket) merge(o *bucket) {
	b.Totals.add(o.Totals)
	b.SolveSum += o.SolveSum
	b.SolveCount += o.SolveCount
	for t, c := range o.Hours {
		if d := b.Hours[t]; d != nil {
			d.add(*c)
		} else {
			cc := *c
			b.Hours[t] = &cc
		}
	}
	for _, pair := range []struct{ dst, src map[string]int64 }{
		{b.Rules, o.Rules}, {b.UAs, o.UAs}, {b.Paths, o.Paths}, {b.IPs, o.IPs},
	} {
		for k, v := range pair.src {
			pair.dst[k] += v
		}
		capMap(pair.dst)
	}
}

func cloneMap(m map[string]int64) map[string]int64 {
	out := make(map[string]int64, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// Run saves the statistics every 30 seconds (when something changed) and
// once more when ctx is canceled. It blocks until then.
func (s *Stats) Run(ctx context.Context) {
	t := time.NewTicker(saveEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			if err := s.Save(); err != nil {
				slog.Error("saving stats failed", "err", err)
			}
			return
		case <-t.C:
			s.mu.Lock()
			dirty := s.dirty
			s.mu.Unlock()
			if dirty {
				if err := s.Save(); err != nil {
					slog.Warn("saving stats failed", "err", err)
				}
			}
		}
	}
}
