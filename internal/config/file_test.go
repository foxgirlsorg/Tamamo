package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func mustValid(t *testing.T, c *Config) *Config {
	t.Helper()
	c.Secret = "s"
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	return c
}

func asJSON(c *Config) string {
	b, _ := json.MarshalIndent(c, "", " ")
	return string(b)
}

func roundTrip(t *testing.T, c *Config) (*Config, string) {
	t.Helper()
	b, err := MarshalConfigYAML(c)
	if err != nil {
		t.Fatal(err)
	}
	back, err := ParseConfigYAML(b)
	if err != nil {
		t.Fatalf("%v\n%s", err, b)
	}
	return mustValid(t, back), string(b)
}

func TestFileRoundTripDefaults(t *testing.T) {
	c := mustValid(t, Defaults())
	back, y := roundTrip(t, c)
	if asJSON(c) != asJSON(back) {
		t.Fatalf("defaults changed in a round trip:\n%s", y)
	}
	for _, want := range []string{"server:", "listen: :8923", "rules:", "- name: Check everyone else", "language: auto", "translations: {}", "sites: []"} {
		if !strings.Contains(y, want) {
			t.Errorf("file lacks %q:\n%s", want, y)
		}
	}
	if strings.Contains(y, " id:") || strings.Contains(y, "secret:") || strings.Contains(y, "own_") {
		t.Errorf("file has IDs, own_ flags or the secret:\n%s", y)
	}
}

func TestFileRoundTripSites(t *testing.T) {
	c := Defaults()
	c.Page.Translations["ru"] = func() PageTranslation { tr := c.Page.Translations["ru"]; tr.Title = "Минутку"; return tr }()
	delete(c.Page.Translations, "uk")
	c.Page.Translations["de"] = PageTranslation{Title: "Einen Moment"}
	c.Sites = []Site{
		{Name: "My Blog", Hosts: []string{"blog.example.com"}, Target: "http://blog:8080",
			OwnProtection: true, Protection: c.Protection,
			OwnRules: true, Rules: []Rule{{Name: "Block everything", Enabled: true, Action: ActionBlock}},
			OwnPage: true, Page: clonePage(c.Page)},
		{Name: "Shop", Hosts: []string{"shop.example.com", "*.shop.example.com"}},
	}
	c.Sites[0].Protection.Difficulty = 6
	c.Sites[0].Page.Title = "Blog check"
	c.Sites[0].Page.Language = "de"
	c = mustValid(t, c)
	if c.Sites[0].ID != "my-blog" {
		t.Fatalf("id: %q", c.Sites[0].ID)
	}
	back, y := roundTrip(t, c)
	if asJSON(c) != asJSON(back) {
		t.Fatalf("round trip changed the config:\n%s", y)
	}
	for _, want := range []string{"- name: My Blog", "difficulty: 6", "title: Blog check", "language: de", "uk: off", "title: Минутку"} {
		if !strings.Contains(y, want) {
			t.Errorf("file lacks %q:\n%s", want, y)
		}
	}
	// The site's protection lists only what differs.
	i := strings.Index(y, "- name: My Blog")
	if strings.Contains(y[i:i+400], "pass_hours") {
		t.Errorf("site protection repeats global settings:\n%s", y[i:])
	}
}

func TestFileSiteInheritsGlobalEdits(t *testing.T) {
	y := `
protection:
  difficulty: 3
sites:
  - name: Blog
    hosts: [blog.example.com]
    protection:
      pass_hours: 2
`
	c, err := ParseConfigYAML([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	c = mustValid(t, c)
	p := c.Sites[0].Protection
	if p.Difficulty != 3 || p.PassHours != 2 || !c.Sites[0].OwnProtection || c.Sites[0].OwnRules {
		t.Fatalf("got %+v", c.Sites[0])
	}
	if len(c.Rules) != len(DefaultRules()) {
		t.Fatal("left-out rules should keep the defaults")
	}
}

func TestFileErrorsNameTheLine(t *testing.T) {
	for y, want := range map[string]string{
		"server:\n  listne: x\n":                            `line 2: unknown setting "listne" in server (did you mean "listen"?)`,
		"protection:\n  difficulty: hard\n":                 "line 2",
		"sites:\n  - site: abc\n":                           "known by their name",
		"page:\n  translations:\n    de:\n      titel: x\n": `unknown setting "titel"`,
		"bogus: 1\n": `unknown setting "bogus"`,
	} {
		_, err := ParseConfigYAML([]byte(y))
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: got %v, want %q", y, err, want)
		}
	}
	c := Defaults()
	c.Page.Language = "fr"
	c.Secret = "s"
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "fr") {
		t.Errorf("unknown page language accepted: %v", err)
	}
}

func TestPickLanguageManual(t *testing.T) {
	c := mustValid(t, Defaults())
	pg := c.Page
	if got := pg.PickLanguage("uk,en;q=0.5"); got != "uk" {
		t.Fatalf("auto: %q", got)
	}
	pg.Language = "ru"
	if got := pg.PickLanguage("uk,en;q=0.5"); got != "ru" {
		t.Fatalf("forced ru: %q", got)
	}
	pg.Language = "en"
	if got := pg.PickLanguage("uk"); got != "" {
		t.Fatalf("forced main: %q", got)
	}
}

func TestRulesFragmentBySiteName(t *testing.T) {
	c := Defaults()
	c.Sites = []Site{{Name: "Blog", Hosts: []string{"blog.example.com"}}}
	c = mustValid(t, c)
	y := "rules: []\nsites:\n  - name: blog\n    rules:\n      - name: Block\n        action: block\n"
	if err := ApplyRulesYAML(c, []byte(y)); err != nil {
		t.Fatal(err)
	}
	if !c.Sites[0].OwnRules || c.Sites[0].Rules[0].Action != ActionBlock || len(c.Rules) != 0 {
		t.Fatalf("got %+v", c.Sites[0])
	}
	if err := ApplyRulesYAML(c, []byte("rules: []\nsites:\n  - name: Nope\n")); err == nil || !strings.Contains(err.Error(), "Blog") {
		t.Fatalf("unknown site: %v", err)
	}
}

func TestManagerReloadKeepsHandEdits(t *testing.T) {
	dir := t.TempDir()
	m, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	var renames map[string]string
	m.OnSiteRename(func(r map[string]string) { renames = r })
	p := filepath.Join(dir, FileName)
	hand := "# my notes\nsites:\n  - name: Blog\n    hosts: [blog.example.com]\n"
	if err := os.WriteFile(p, []byte(hand), 0o600); err != nil {
		t.Fatal(err)
	}
	if ok, err := m.checkDisk(); !ok || err != nil {
		t.Fatal(ok, err)
	}
	if b, _ := os.ReadFile(p); string(b) != hand {
		t.Fatal("reload rewrote the hand-written file")
	}
	if m.ForHost("blog.example.com").ID != "blog" {
		t.Fatal("site not picked up")
	}
	if err := os.WriteFile(p, []byte(strings.Replace(hand, "Blog", "Journal", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if ok, err := m.checkDisk(); !ok || err != nil {
		t.Fatal(ok, err)
	}
	if renames["blog"] != "journal" {
		t.Fatalf("renames: %v", renames)
	}
}
