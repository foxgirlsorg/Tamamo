package admin

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/foxgirlsorg/tamamo/internal/config"
)

// hasIDLine reports whether any line of a rules file sets an "id:" key.
// Rules are written without IDs: they are derived from names.
func hasIDLine(yml string) bool {
	for _, line := range strings.Split(yml, "\n") {
		if strings.HasPrefix(strings.TrimLeft(line, " -"), "id:") {
			return true
		}
	}
	return false
}

func putRulesFile(e *env, c *http.Cookie, yml string) resp {
	b, _ := json.Marshal(map[string]string{"yaml": yml})
	return e.do("PUT", "/api/rules/file", string(b), c, true)
}

func TestRulesFileAPI(t *testing.T) {
	e := newEnv(t)
	c := e.setup()
	g := e.do("GET", "/api/rules/file", "", c, false)
	y, _ := g.body["yaml"].(string)
	if g.code != 200 || !strings.Contains(y, "rules:") ||
		!strings.Contains(y, "name: Check everyone else") || hasIDLine(y) || g.body["path"] != e.cfg.ConfigPath() {
		t.Fatalf("get: %d %s", g.code, g.raw)
	}
	if e.do("GET", "/api/rules/file", "", nil, false).code != 401 {
		t.Fatal("rules file readable without a session")
	}
	if e.do("PUT", "/api/rules/file", `{"yaml":"rules: []"}`, c, false).code != 403 {
		t.Fatal("PUT without the CSRF header accepted")
	}

	r := putRulesFile(e, c, "rules:\n  - name: Only\n    action: block\n    paths: [/x]\n")
	if r.code != 200 || !strings.Contains(r.body["yaml"].(string), "name: Only") || hasIDLine(r.body["yaml"].(string)) {
		t.Fatalf("put: %d %s", r.code, r.raw)
	}
	if rs := e.cfg.Get().Rules; len(rs) != 1 || rs[0].Action != config.ActionBlock || rs[0].ID != "only" {
		t.Fatalf("rules not applied, or ID not derived from the name: %+v", rs)
	}
	// The settings file on disk now carries the rules.
	disk, _ := os.ReadFile(e.cfg.ConfigPath())
	if !strings.Contains(string(disk), "name: Only") || !strings.Contains(string(disk), "rules:") || hasIDLine(string(disk)) {
		t.Fatalf("tamamo.yaml does not carry the rules:\n%s", disk)
	}
	// GET /api/config still carries the rules, with the derived ID.
	if g := e.do("GET", "/api/config", "", c, false); !strings.Contains(g.raw, `"id":"only"`) {
		t.Fatal("rules missing from /api/config")
	}

	// A bad rule is a 400 with its line, and nothing changes.
	r = putRulesFile(e, c, "rules:\n  - name: X\n    action: maybe\n")
	if r.code != 400 || !strings.HasPrefix(r.body["error"].(string), "line 3:") {
		t.Fatalf("bad yaml: %d %s", r.code, r.raw)
	}
	if e.cfg.Get().Rules[0].ID != "only" {
		t.Fatal("bad yaml changed the rules")
	}
}

func TestRulesFileClientIDsIgnored(t *testing.T) {
	e := newEnv(t)
	c := e.setup()
	// A client-sent id is ignored: the ID comes from the name.
	r := putRulesFile(e, c, "rules:\n  - id: my-own-id\n    name: Renamed Rule\n    action: allow\n")
	if r.code != 200 {
		t.Fatalf("put: %d %s", r.code, r.raw)
	}
	if rs := e.cfg.Get().Rules; len(rs) != 1 || rs[0].ID != "renamed-rule" {
		t.Fatalf("client id was not replaced by the name-derived one: %+v", rs)
	}
	// Rules with the same name get suffixed IDs.
	r = putRulesFile(e, c, "rules:\n  - name: Block bots\n    action: block\n    user_agents: [bad]\n  - name: Block bots\n    action: block\n    user_agents: [worse]\n")
	if r.code != 200 {
		t.Fatalf("put duplicates: %d %s", r.code, r.raw)
	}
	rs := e.cfg.Get().Rules
	if len(rs) != 2 || rs[0].ID != "block-bots" || rs[1].ID != "block-bots-2" {
		t.Fatalf("duplicate names not deduplicated: %+v", rs)
	}
}

func TestRulesFileSites(t *testing.T) {
	e := newEnv(t)
	c := e.setup()
	if err := e.cfg.Update(func(cf *config.Config) error {
		cf.Sites = []config.Site{{ID: "ignored-client-id", Name: "My Blog", Hosts: []string{"blog.example.com"}}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// Site IDs come from the name, whatever the client sent.
	if st := e.cfg.Get().Sites; len(st) != 1 || st[0].ID != "my-blog" {
		t.Fatalf("site ID not derived from its name: %+v", st)
	}

	// Global rules plus this site's own rules, the site named by its name.
	yml := "rules:\n  - name: Global Block\n    action: block\n    paths: [/x]\n" +
		"sites:\n  - name: My Blog\n    rules:\n      - name: Block all\n        action: block\n"
	if r := putRulesFile(e, c, yml); r.code != 200 {
		t.Fatalf("put with sites: %d %s", r.code, r.raw)
	}
	cfg := e.cfg.Get()
	if len(cfg.Rules) != 1 || cfg.Rules[0].ID != "global-block" {
		t.Fatalf("global rules: %+v", cfg.Rules)
	}
	st := cfg.Sites[0]
	if !st.OwnRules || len(st.Rules) != 1 || st.Rules[0].ID != "block-all" || st.Rules[0].Action != config.ActionBlock {
		t.Fatalf("site rules not applied: %+v", st)
	}
	disk, _ := os.ReadFile(e.cfg.ConfigPath())
	for _, want := range []string{"sites:", "- name: My Blog", "name: Block all"} {
		if !strings.Contains(string(disk), want) {
			t.Fatalf("tamamo.yaml lacks %q:\n%s", want, disk)
		}
	}

	// Naming a site that does not exist is refused, and lists the sites.
	r := putRulesFile(e, c, "rules: []\nsites:\n  - name: Nope\n    rules: []\n")
	if r.code != 400 || !strings.Contains(r.body["error"].(string), `there is no site called "Nope"`) {
		t.Fatalf("unknown site: %d %s", r.code, r.raw)
	}

	// Renaming a site changes its ID and keeps its rules.
	if err := e.cfg.Update(func(cf *config.Config) error {
		cf.Sites[0].Name = "My Journal"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	st = e.cfg.Get().Sites[0]
	if st.ID != "my-journal" || !st.OwnRules || len(st.Rules) != 1 {
		t.Fatalf("rename: id %q, own rules %v, rules %d", st.ID, st.OwnRules, len(st.Rules))
	}

	// Site names must be unique.
	err := e.cfg.Update(func(cf *config.Config) error {
		cf.Sites = append(cf.Sites, config.Site{Name: "my journal", Hosts: []string{"other.example.com"}})
		return nil
	})
	if err == nil {
		t.Fatal("two sites with the same name accepted")
	}
}

func TestSiteIDsDeduplicated(t *testing.T) {
	e := newEnv(t)
	if err := e.cfg.Update(func(cf *config.Config) error {
		cf.Sites = []config.Site{
			{Name: "My Blog", Hosts: []string{"a.example.com"}},
			{Name: "My  Blog!", Hosts: []string{"b.example.com"}},
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	st := e.cfg.Get().Sites
	if st[0].ID != "my-blog" || st[1].ID != "my-blog-2" {
		t.Fatalf("site IDs: %q, %q", st[0].ID, st[1].ID)
	}
}

func TestPageLanguageWinsOverAutoLanguage(t *testing.T) {
	e := newEnv(t)
	c := e.setup()
	g := e.do("GET", "/api/config", "", c, false)
	cfgMap := g.body["config"].(map[string]any)
	pg := cfgMap["page"].(map[string]any)
	pg["auto_language"] = true
	pg["language"] = "uk"
	body, _ := json.Marshal(cfgMap)
	if r := e.do("PUT", "/api/config", string(body), c, true); r.code != 200 {
		t.Fatalf("put: %d %s", r.code, r.raw)
	}
	if pg := e.cfg.Stored().Page; pg.Language != "uk" || pg.AutoLanguage {
		t.Fatalf("page language %q, auto %v: the explicit language should win", pg.Language, pg.AutoLanguage)
	}
}
