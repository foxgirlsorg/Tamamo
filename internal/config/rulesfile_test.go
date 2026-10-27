package config

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"
)

// idKey finds a rule or site written with an "id:" key.
var idKey = regexp.MustCompile(`(?m)^\s*(- )?id:`)

func TestRulesYAMLRoundTrip(t *testing.T) {
	cfg := Defaults()
	cfg.Sites = []Site{
		{Name: "Blog", Hosts: []string{"blog.example.com"}, OwnRules: true, Rules: []Rule{
			{Name: "Block AI", Enabled: false, Action: ActionBlock, Difficulty: 0,
				Match: Match{UserAgents: []string{"*GPTBot*"}, Methods: []string{"GET", "POST"},
					Headers: []HeaderMatch{{Name: "Accept", Pattern: "*html*"}}}, Note: "Multi\nline"},
			{Name: "Check", Enabled: true, Action: ActionChallenge, Difficulty: 6,
				Match: Match{Paths: []string{"*"}, Headers: []HeaderMatch{{Name: "X-A", Pattern: "1"}, {Name: "x-a", Pattern: "2"}}}},
		}},
		{Name: "Shop", Hosts: []string{"shop.example.com"}},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.Sites[0].ID != "blog" || cfg.Sites[0].Rules[0].ID != "block-ai" {
		t.Fatalf("ids not derived from names: site %q, rule %q", cfg.Sites[0].ID, cfg.Sites[0].Rules[0].ID)
	}
	b, err := MarshalRulesYAML(cfg)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{
		"# Rules, checked top to bottom", "\nrules:", "\nsites:", "- name: Blog", "- name: Block AI",
		"paths: [/robots.txt, /.well-known/*, /favicon.ico]", "paths: ['*']", "enabled: false",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in:\n%s", want, s)
		}
	}
	if idKey.MatchString(s) {
		t.Errorf("rules were written with IDs:\n%s", s)
	}
	if strings.Contains(s, "- name: Shop") {
		t.Error("a site without its own rules was written")
	}

	back := cfg.Clone()
	back.Rules = nil
	back.Sites[0].Rules, back.Sites[0].OwnRules = nil, false
	back.Sites[1].OwnRules = true
	if err := ApplyRulesYAML(back, b); err != nil {
		t.Fatalf("%v\n%s", err, s)
	}
	if err := back.Validate(); err != nil {
		t.Fatal(err)
	}
	if len(back.Rules) != len(cfg.Rules) || back.Rules[0].ID != cfg.Rules[0].ID {
		t.Errorf("global rules differ after the round trip")
	}
	if !back.Sites[0].OwnRules || len(back.Sites[0].Rules) != 2 {
		t.Fatalf("site rules: %+v", back.Sites[0].Rules)
	}
	r0, r1 := back.Sites[0].Rules[0], back.Sites[0].Rules[1]
	if r0.Enabled || r0.Note != "Multi\nline" || r0.Match.Headers[0].Name != "Accept" || len(r0.Match.Methods) != 2 {
		t.Errorf("rule 0: %+v", r0)
	}
	if r1.Difficulty != 6 || len(r1.Match.Headers) != 2 || r1.Match.Headers[1].Pattern != "2" {
		t.Errorf("rule 1: %+v", r1)
	}
	again, _ := MarshalRulesYAML(back)
	if string(again) != s {
		t.Errorf("second marshal differs:\n%s\n---\n%s", again, s)
	}
	if back.Sites[1].OwnRules {
		t.Error("a site the file doesn't list should follow the global rules")
	}
}

func TestRulesYAMLSiteByNameIDOrHost(t *testing.T) {
	base := Defaults()
	base.Sites = []Site{{Name: "My Blog", Hosts: []string{"blog.example.com"}}}
	if err := base.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"My Blog", "my blog", "my-blog", "blog.example.com"} {
		c := base.Clone()
		y := "rules: []\nsites:\n  - name: " + key + "\n    rules:\n      - name: Block\n        action: block\n"
		if err := ApplyRulesYAML(c, []byte(y)); err != nil {
			t.Errorf("%q: %v", key, err)
			continue
		}
		if err := c.Validate(); err != nil {
			t.Fatal(err)
		}
		if !c.Sites[0].OwnRules || len(c.Sites[0].Rules) != 1 {
			t.Errorf("%q: site rules not applied: %+v", key, c.Sites[0])
		}
	}
}

func TestRulesYAMLKeyNames(t *testing.T) {
	// "rules:" is the name; "global:" and "bots:" are still read.
	want := []string{"Allow API", "Block bad"}
	for _, key := range []string{"rules", "global", "bots"} {
		cfg := Defaults()
		y := key + ":\n  - name: Allow API\n    action: allow\n    path_regex: ^/api/\n  - name: Block bad\n    action: DENY\n    user_agent_regex: (?i)evilbot\n"
		if err := ApplyRulesYAML(cfg, []byte(y)); err != nil {
			t.Fatalf("%s: %v", key, err)
		}
		if err := cfg.Validate(); err != nil {
			t.Fatal(err)
		}
		var names []string
		for _, r := range cfg.Rules {
			names = append(names, r.Name)
		}
		if !reflect.DeepEqual(names, want) {
			t.Errorf("%s: rules %v", key, names)
		}
	}
}

func TestRulesYAMLAlternativeKeys(t *testing.T) {
	cfg := Defaults()
	err := ApplyRulesYAML(cfg, []byte(`
rules:
  - name: allow-api
    path_regex: ^/api/
    action: ALLOW
  - name: deny-bad
    user_agent_regex: (?i)evilbot
    remote_addresses: [10.0.0.0/8]
    action: DENY
  - name: Generic Browser
    user_agent_regex: Mozilla
    action: CHALLENGE
    challenge:
      difficulty: 5
      algorithm: fast
dnsbl: false
`))
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	r := cfg.Rules
	if len(r) != 3 || r[0].Action != ActionAllow || r[0].Match.Paths[0] != "re:^/api/" || r[0].ID != "allow-api" || !r[0].Enabled {
		t.Fatalf("rule 0: %+v", r[0])
	}
	if r[1].Action != ActionBlock || r[1].Match.UserAgents[0] != "re:(?i)evilbot" || r[1].Match.IPs[0] != "10.0.0.0/8" {
		t.Fatalf("rule 1: %+v", r[1])
	}
	if r[2].Action != ActionChallenge || r[2].Difficulty != 5 || r[2].ID != "generic-browser" {
		t.Fatalf("rule 2: %+v", r[2])
	}
}

func TestRuleIDsFromNamesAreUnique(t *testing.T) {
	cfg := Defaults()
	if err := ApplyRulesYAML(cfg, []byte("rules:\n  - name: Block\n    action: block\n  - name: Block\n    action: allow\n")); err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.Rules[0].ID != "block" || cfg.Rules[1].ID != "block-2" {
		t.Fatalf("ids: %q %q", cfg.Rules[0].ID, cfg.Rules[1].ID)
	}
}

func TestRulesYAMLErrors(t *testing.T) {
	cfg := Defaults()
	cfg.Sites = []Site{{Name: "One", Hosts: []string{"one.example"}}}
	cases := map[string]string{
		"rules:\n  - name: x\n    action: WEIGH\n":                        "line 3: WEIGH isn't supported, use allow/challenge/block",
		"rules:\n  - name: x\n    action: allow\n    paths: [\"re:(\"]\n": "line 2:",
		"rules: []\nsites:\n  - name: nope\n    rules: []\n":              `line 3: there is no site called "nope" (sites: One)`,
		"rules:\n  - name: x\n    action: allow\n    color: red\n":        `line 4: unknown key "color"`,
		"rules:\n  - name: x\n":                                           "line 2: rule \"x\" needs an action",
		"rules:\n  - name: x\n    action: allow\n   bad indent: [\n":      "line ",
		"":            "empty",
		"sites: []\n": "the global rules are missing",
		"rules:\n  - name: x\n    action: allow\n    enabled: maybe\n":                    "line 4: enabled must be true or false",
		"rules: []\nsites:\n  - name: One\n    rules: []\n  - name: One\n    rules: []\n": `line 5: site "One" is listed twice`,
	}
	for in, want := range cases {
		err := ApplyRulesYAML(cfg.Clone(), []byte(in))
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: got %v, want %q", in, err, want)
		}
	}
}

func TestHotReload(t *testing.T) {
	dir := t.TempDir()
	m, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	notified := make(chan *Config, 4)
	m.Subscribe(func(c *Config) { notified <- c })

	// Our own writes don't count as changes.
	if err := m.Update(func(c *Config) error { c.Protection.Difficulty = 3; return nil }); err != nil {
		t.Fatal(err)
	}
	<-notified
	if ok, err := m.checkDisk(); ok || err != nil {
		t.Fatalf("self-write triggered a reload: %v %v", ok, err)
	}

	path := filepath.Join(dir, FileName)
	write := func(s string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
		// Make sure the mtime moves even on coarse file systems.
		future := time.Now().Add(time.Duration(len(s)) * time.Second)
		_ = os.Chtimes(path, future, future)
	}
	// A hand edit is reloaded; settings it doesn't mention are the defaults.
	write("protection:\n  difficulty: 3\nrules:\n  - name: Edited on disk\n    action: block\n    paths: [/secret]\n")
	if ok, err := m.checkDisk(); !ok || err != nil {
		t.Fatalf("edit not reloaded: %v %v", ok, err)
	}
	if r := m.Get().Rules; len(r) != 1 || r[0].ID != "edited-on-disk" {
		t.Fatalf("rules after reload: %+v", r)
	}
	if c := <-notified; c.Rules[0].ID != "edited-on-disk" {
		t.Fatal("subscriber got the old config")
	}
	if m.Get().Protection.Difficulty != 3 {
		t.Fatal("protection setting lost on reload")
	}

	// A broken file keeps the running config and is reported once.
	write("rules:\n  - name: x\n    action: nope\n")
	if ok, err := m.checkDisk(); ok || err == nil || !strings.Contains(err.Error(), "line 3") {
		t.Fatalf("broken file: %v %v", ok, err)
	}
	if m.Get().Rules[0].ID != "edited-on-disk" {
		t.Fatal("running config replaced by a broken file")
	}
	if ok, err := m.checkDisk(); ok || err != nil {
		t.Fatalf("broken file reported twice: %v %v", ok, err)
	}

	// YAML type errors name their line too.
	write("protection:\n  difficulty: hard\n")
	if _, err := m.checkDisk(); err == nil || !strings.Contains(err.Error(), "line 2") {
		t.Fatalf("type error without line: %v", err)
	}

	// Removing the settings file writes it again from the running settings.
	write("protection:\n  difficulty: 7\nrules: []\n")
	if ok, err := m.checkDisk(); !ok || err != nil {
		t.Fatalf("second edit: %v %v", ok, err)
	}
	if m.Get().Protection.Difficulty != 7 || len(m.Get().Rules) != 0 {
		t.Fatalf("after reload: difficulty %d, %d rules", m.Get().Protection.Difficulty, len(m.Get().Rules))
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	_, _ = m.checkDisk()
	y, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("tamamo.yaml not rewritten: %v", err)
	}
	if back, err := ParseConfigYAML(y); err != nil || back.Protection.Difficulty != 7 {
		t.Fatalf("rewritten file does not hold the running settings: %v\n%s", err, y)
	}

	// Watch runs the same check on a timer.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go m.watch(ctx, 20*time.Millisecond)
	write("rules:\n  - name: W\n    action: allow\n")
	deadline := time.After(5 * time.Second)
	for {
		if r := m.Get().Rules; len(r) == 1 && r[0].ID == "w" {
			break
		}
		select {
		case <-deadline:
			t.Fatal("Watch did not reload")
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func TestAdminDomains(t *testing.T) {
	got, err := NormalizeAdminDomains([]string{" Admin.Example.com. ", "", "*.example.org", "admin.example.com"})
	if err != nil || !reflect.DeepEqual(got, []string{"admin.example.com", "*.example.org"}) {
		t.Fatalf("%v %v", got, err)
	}
	for _, bad := range []string{"https://a.com", "a.com:8081", "a.com/x", "a..com", "*a.com", "a.*.com", "-a.com"} {
		if _, err := NormalizeAdminDomains([]string{bad}); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	d := []string{"admin.example.com", "*.example.org"}
	for host, want := range map[string]bool{
		"admin.example.com": true, "ADMIN.example.com:8081": true, "x.example.org": true, "a.b.example.org": true,
		"example.org": false, "evil.com": false, "admin.example.com.evil.com": false, "": false,
	} {
		if AdminHostAllowed(d, host) != want {
			t.Errorf("%q: want %v", host, want)
		}
	}
	if !AdminHostAllowed(nil, "anything") {
		t.Error("empty list should allow every host")
	}
}

func TestAdminDomainEnv(t *testing.T) {
	t.Setenv("TAMAMO_ADMIN_DOMAIN", "Admin.Example.com, ops.example.com")
	m, err := Load(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if got := m.Get().Admin.Domains; !reflect.DeepEqual(got, []string{"admin.example.com", "ops.example.com"}) {
		t.Fatalf("domains %v", got)
	}
	if m.Locked()["admin.domains"] != "TAMAMO_ADMIN_DOMAIN" {
		t.Fatalf("not locked: %v", m.Locked())
	}
	t.Setenv("TAMAMO_ADMIN_DOMAIN", "https://bad")
	if _, err := Load(t.TempDir()); err == nil {
		t.Fatal("bad env domain accepted")
	}
}
