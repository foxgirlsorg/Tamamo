package stats

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/foxgirlsorg/tamamo/internal/config"
)

func newTest(t *testing.T) (*Stats, *config.Manager, string) {
	t.Helper()
	dir := t.TempDir()
	mgr, err := config.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := mgr.Update(func(c *config.Config) error { c.Stats.Enabled = true; return nil }); err != nil {
		t.Fatal(err)
	}
	s, err := New(dir, mgr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, mgr, dir
}

func TestStatsOffByDefault(t *testing.T) {
	dir := t.TempDir()
	mgr, err := config.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if config.Defaults().Stats.Enabled || mgr.Get().Stats.Enabled {
		t.Fatal("stats enabled by default")
	}
	s, err := New(dir, mgr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	s.Record(Event{Kind: KindBlock, IP: "1.2.3.4", Path: "/x"})
	snap := s.Snapshot("")
	if snap.Enabled || snap.Totals != (Counters{}) || len(snap.Events) != 0 {
		t.Errorf("recorded while off by default: enabled=%v totals=%+v events=%d", snap.Enabled, snap.Totals, len(snap.Events))
	}
}

// openAt opens the store in dir without a config manager (defaults apply)
// and closes it when the test ends.
func openAt(t *testing.T, dir string) *Stats {
	t.Helper()
	s, err := New(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestRecordAndSnapshot(t *testing.T) {
	s, _, dir := newTest(t)
	s.Record(Event{Kind: KindChallenge, IP: "1.2.3.4", Path: "/a", UA: "ua1", Rule: "r1"})
	s.Record(Event{Kind: KindChallenge, IP: "1.2.3.4", Path: "/a", UA: "ua1", Rule: "r1"})
	s.Record(Event{Kind: KindSolve, IP: "1.2.3.4", SolveMs: 100})
	s.Record(Event{Kind: KindSolve, IP: "1.2.3.4", SolveMs: 300})
	s.Record(Event{Kind: KindPass, Rule: "r1"})
	s.Record(Event{Kind: KindAllow})
	s.Record(Event{Kind: KindBlock, UA: strings.Repeat("x", 400), Path: "/b"})
	s.Record(Event{Kind: KindFail})
	s.Record(Event{Kind: "bogus"})

	snap := s.Snapshot("")
	want := Counters{Requests: 5, Passed: 1, Allowed: 1, Challenged: 2, Solved: 2, Failed: 1, Blocked: 1}
	if snap.Totals != want || snap.Last24h != want {
		t.Fatalf("totals %+v / last24h %+v, want %+v", snap.Totals, snap.Last24h, want)
	}
	if len(snap.Hours) != 24 || len(snap.Days) != 7 {
		t.Fatalf("hours %d days %d", len(snap.Hours), len(snap.Days))
	}
	if snap.Hours[23].Counters != want {
		t.Errorf("current hour %+v", snap.Hours[23].Counters)
	}
	if snap.Days[6].Counters != want {
		t.Errorf("today %+v", snap.Days[6].Counters)
	}
	if snap.AvgSolveMs != 200 {
		t.Errorf("avg %v", snap.AvgSolveMs)
	}
	if len(snap.TopRules) != 1 || snap.TopRules[0] != (Named{"r1", 3}) {
		t.Errorf("top rules %+v", snap.TopRules)
	}
	if len(snap.TopIPs) != 1 || snap.TopIPs[0] != (Named{"1.2.3.4", 2}) {
		t.Errorf("top ips %+v", snap.TopIPs)
	}
	// challenge, challenge, solve, solve, block, fail are kept; newest first.
	if len(snap.Events) != 6 || snap.Events[0].Kind != KindFail || snap.Events[5].Kind != KindChallenge {
		t.Errorf("events %+v", snap.Events)
	}
	if len(snap.Events[1].UA) != 300 {
		t.Errorf("UA not truncated: %d", len(snap.Events[1].UA))
	}

	// JSON shape: embedded counters are flattened.
	b, _ := json.Marshal(snap.Hours[23])
	if !strings.Contains(string(b), `"t":`) || !strings.Contains(string(b), `"requests":5`) {
		t.Errorf("bucket json %s", b)
	}

	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	s2 := openAt(t, dir)
	snap2 := s2.Snapshot("")
	if snap2.Totals != want || len(snap2.Events) != 6 || snap2.Events[0].Kind != KindFail {
		t.Errorf("reloaded %+v, %d events", snap2.Totals, len(snap2.Events))
	}

	s.Reset()
	if s.Snapshot("").Totals != (Counters{}) {
		t.Error("reset did not clear totals")
	}
}

func TestDisabledAndNoIPs(t *testing.T) {
	s, mgr, _ := newTest(t)
	if err := mgr.Update(func(c *config.Config) error { c.Stats.StoreIPs = false; return nil }); err != nil {
		t.Fatal(err)
	}
	s.Record(Event{Kind: KindBlock, IP: "9.9.9.9"})
	snap := s.Snapshot("")
	if len(snap.TopIPs) != 0 || snap.Events[0].IP != "" {
		t.Errorf("IP stored: %+v %+v", snap.TopIPs, snap.Events)
	}
	if err := mgr.Update(func(c *config.Config) error { c.Stats.Enabled = false; return nil }); err != nil {
		t.Fatal(err)
	}
	s.Record(Event{Kind: KindBlock})
	if s.Snapshot("").Totals.Blocked != 1 {
		t.Error("recorded while disabled")
	}
}

func TestRingAndCaps(t *testing.T) {
	s, mgr, _ := newTest(t)
	if err := mgr.Update(func(c *config.Config) error { c.Stats.RecentEvents = 10; return nil }); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 1500; i++ {
		s.Record(Event{Kind: KindChallenge, Path: "/p" + strconv.Itoa(i)})
	}
	snap := s.Snapshot("")
	if len(snap.Events) != 10 || snap.Events[0].Path != "/p1499" || snap.Events[9].Path != "/p1490" {
		t.Errorf("ring: %d events, first %q", len(snap.Events), snap.Events[0].Path)
	}
	s.mu.Lock()
	n := len(s.all.Paths)
	s.mu.Unlock()
	if n > maxTopItems {
		t.Errorf("paths map has %d entries", n)
	}
	if err := mgr.Update(func(c *config.Config) error { c.Stats.RecentEvents = 20; return nil }); err != nil {
		t.Fatal(err)
	}
	s.Record(Event{Kind: KindBlock, Path: "/last"})
	snap = s.Snapshot("")
	if len(snap.Events) != 11 || snap.Events[0].Path != "/last" || snap.Events[1].Path != "/p1499" {
		t.Errorf("after resize: %d events", len(snap.Events))
	}
}

func TestHourPruning(t *testing.T) {
	s, _, _ := newTest(t)
	now := time.Now()
	s.Record(Event{Kind: KindAllow, Time: now.Add(-10 * 24 * time.Hour)})
	s.Record(Event{Kind: KindAllow, Time: now})
	s.mu.Lock()
	n := len(s.all.Hours)
	s.mu.Unlock()
	if n != 1 {
		t.Errorf("old bucket not pruned: %d buckets", n)
	}
	if s.Snapshot("").Totals.Allowed != 2 {
		t.Error("totals should keep old events")
	}
}

func TestPerSite(t *testing.T) {
	s, _, dir := newTest(t)
	s.Record(Event{Kind: KindChallenge, Site: "a", Path: "/x"})
	s.Record(Event{Kind: KindChallenge, Site: "a", Path: "/x"})
	s.Record(Event{Kind: KindBlock, Site: "b", Path: "/y"})
	all := s.Snapshot("")
	if all.Totals.Requests != 3 || len(all.Sites) != 2 || all.Sites[0] != (SiteCounters{"a", Counters{Requests: 2, Challenged: 2}}) {
		t.Fatalf("all: %+v %+v", all.Totals, all.Sites)
	}
	a := s.Snapshot("a")
	if a.Totals.Challenged != 2 || a.Totals.Blocked != 0 || len(a.Events) != 2 || len(a.Sites) != 0 || a.TopPaths[0].Name != "/x" {
		t.Fatalf("site a: %+v", a)
	}
	if n := s.Snapshot("nope"); n.Totals != (Counters{}) || len(n.Hours) != 24 || len(n.Events) != 0 {
		t.Fatalf("unknown site: %+v", n)
	}
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	s2 := openAt(t, dir)
	if got := s2.Snapshot("b"); got.Totals.Blocked != 1 || got.Hours[23].Blocked != 1 {
		t.Fatalf("reloaded b: %+v", got.Totals)
	}
	for i := 0; i < maxSites+50; i++ {
		s.Record(Event{Kind: KindAllow, Site: "s" + strconv.Itoa(i)})
	}
	s.mu.Lock()
	n := len(s.sites)
	s.mu.Unlock()
	if n > maxSites {
		t.Fatalf("%d sites tracked", n)
	}
}

func TestCloseRoundTrip(t *testing.T) {
	s, _, dir := newTest(t)
	now := time.Now()
	s.Record(Event{Kind: KindChallenge, Site: "a", IP: "1.1.1.1", Path: "/p", UA: "ua", Rule: "r", Time: now})
	s.Record(Event{Kind: KindSolve, Site: "a", SolveMs: 250, Time: now})
	s.Record(Event{Kind: KindBlock, Site: "b", Path: "/q", Time: now})
	before := s.Snapshot("a")
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}

	s2 := openAt(t, dir)
	after := s2.Snapshot("a")
	if after.Totals != before.Totals || after.Last24h != before.Last24h || after.AvgSolveMs != before.AvgSolveMs {
		t.Errorf("totals %+v, want %+v", after.Totals, before.Totals)
	}
	if !after.Since.Equal(before.Since) {
		t.Errorf("since %v, want %v", after.Since, before.Since)
	}
	if after.Hours[23] != before.Hours[23] || after.Days[6] != before.Days[6] {
		t.Errorf("hours %+v, want %+v", after.Hours[23], before.Hours[23])
	}
	if len(after.Events) != 2 || after.Events[0].Kind != KindSolve || after.Events[1].IP != "1.1.1.1" ||
		!after.Events[1].Time.Equal(now.UTC()) {
		t.Errorf("events %+v", after.Events)
	}
	if len(after.TopRules) != 1 || after.TopRules[0] != (Named{"r", 1}) || len(after.TopIPs) != 1 {
		t.Errorf("tops %+v %+v", after.TopRules, after.TopIPs)
	}
	if all := s2.Snapshot(""); len(all.Sites) != 2 || all.Totals.Requests != 2 {
		t.Errorf("all sites %+v %+v", all.Sites, all.Totals)
	}
}

func TestCorruptStoreStartsFresh(t *testing.T) {
	dir := t.TempDir()
	garbage := strings.Repeat("this is not a sqlite database ", 100)
	if err := os.WriteFile(filepath.Join(dir, dbFile), []byte(garbage), 0o600); err != nil {
		t.Fatal(err)
	}
	s := openAt(t, dir)
	if s.Snapshot("").Totals != (Counters{}) {
		t.Fatal("corrupt database was not ignored")
	}
	s.Record(Event{Kind: KindBlock})
	if err := s.Save(); err != nil {
		t.Fatalf("save after recovery: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, dbFile+".corrupt")); err != nil {
		t.Errorf("broken database not kept aside: %v", err)
	}
}

func TestUnopenablePathIsError(t *testing.T) {
	if _, err := New(filepath.Join(t.TempDir(), "missing"), nil); err == nil {
		t.Fatal("expected an error for a directory that does not exist")
	}
}

func TestRenameSites(t *testing.T) {
	s, _, dir := newTest(t)
	s.Record(Event{Kind: KindChallenge, Site: "old1", Path: "/a"})
	s.Record(Event{Kind: KindBlock, Site: "old1", Path: "/b"})
	s.Record(Event{Kind: KindBlock, Site: "new", Path: "/c"})
	s.Record(Event{Kind: KindBlock, Site: "keep", Path: "/d"})

	s.RenameSites(map[string]string{"old1": "new", "keep": "kept2"})
	s.mu.Lock()
	dirty := s.dirty
	s.mu.Unlock()
	if !dirty {
		t.Error("RenameSites did not mark the store dirty")
	}

	merged := s.Snapshot("new")
	if merged.Totals.Requests != 3 || merged.Totals.Blocked != 2 || merged.Totals.Challenged != 1 {
		t.Errorf("merged site %+v", merged.Totals)
	}
	if len(merged.Events) != 3 || len(merged.TopPaths) != 3 {
		t.Errorf("merged events %d, paths %+v", len(merged.Events), merged.TopPaths)
	}
	for _, e := range merged.Events {
		if e.Site != "new" {
			t.Errorf("event still labeled %q", e.Site)
		}
	}
	if got := s.Snapshot("old1"); got.Totals != (Counters{}) || len(got.Events) != 0 {
		t.Errorf("old site still present: %+v", got.Totals)
	}
	if got := s.Snapshot("kept2"); got.Totals.Blocked != 1 || len(got.Events) != 1 {
		t.Errorf("renamed site %+v, %d events", got.Totals, len(got.Events))
	}
	if all := s.Snapshot(""); len(all.Sites) != 2 || all.Sites[0].Site != "kept2" || all.Sites[1].Site != "new" {
		t.Errorf("site list %+v", all.Sites)
	}

	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s2 := openAt(t, dir)
	if got := s2.Snapshot("new"); got.Totals.Requests != 3 || len(got.Events) != 3 {
		t.Errorf("reloaded merged site %+v, %d events", got.Totals, len(got.Events))
	}
}

func TestRenameSitesChainAndCollision(t *testing.T) {
	s, _, _ := newTest(t)
	s.Record(Event{Kind: KindAllow, Site: "a"})
	s.Record(Event{Kind: KindAllow, Site: "b"})
	s.Record(Event{Kind: KindAllow, Site: "b"})
	// a -> b and b -> c: a's data must land in b, b's data in c.
	s.RenameSites(map[string]string{"a": "b", "b": "c"})
	if got := s.Snapshot("b").Totals.Allowed; got != 1 {
		t.Errorf("b has %d allowed, want 1", got)
	}
	if got := s.Snapshot("c").Totals.Allowed; got != 2 {
		t.Errorf("c has %d allowed, want 2", got)
	}
	if got := s.Snapshot("a").Totals.Allowed; got != 0 {
		t.Errorf("a has %d allowed, want 0", got)
	}
}
