package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigValidBad(t *testing.T) {
	for name, mut := range map[string]func(c *Config){
		"ftp target":            func(c *Config) { c.Server.Target = "ftp://example.com" },
		"javascript target":     func(c *Config) { c.Server.Target = "javascript:alert(1)" },
		"hostless target":       func(c *Config) { c.Server.Target = "http://" },
		"bad trusted proxy":     func(c *Config) { c.Server.TrustedProxies = []string{"nope"} },
		"cookie name space":     func(c *Config) { c.Protection.CookieName = "bad name" },
		"cookie name semicolon": func(c *Config) { c.Protection.CookieName = "a;b" },
		"cookie name too long":  func(c *Config) { c.Protection.CookieName = strings.Repeat("a", 65) },
		"css breaks out":        func(c *Config) { c.Page.CustomCSS = "</style><script>alert(1)</script>" },
		"css hides credit":      func(c *Config) { c.Page.CustomCSS = ".tm-credit{display:none}" },
		"bad color":             func(c *Config) { c.Page.Light.Accent = "red" },
		"bad custom font":       func(c *Config) { c.Page.CustomFont = "x;}body{display:none" },
		"bad rule regex": func(c *Config) {
			c.Rules = []Rule{{Name: "x", Enabled: true, Action: ActionBlock, Match: Match{Paths: []string{"re:("}}}}
		},
		"site without hosts": func(c *Config) { c.Sites = []Site{{Name: "s"}} },
		"site bad host":      func(c *Config) { c.Sites = []Site{{Name: "s", Hosts: []string{"re:("}}} },
		"site bad target":    func(c *Config) { c.Sites = []Site{{Name: "s", Hosts: []string{"a.test"}, Target: "gopher://x"}} },
		"duplicate host": func(c *Config) {
			c.Sites = []Site{{Name: "a", Hosts: []string{"x.test"}}, {Name: "b", Hosts: []string{"X.test"}}}
		},
		"site bad own rules": func(c *Config) {
			c.Sites = []Site{{Name: "s", Hosts: []string{"a.test"}, OwnRules: true, Rules: []Rule{{Name: "r", Action: "DENY"}}}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			c := Defaults()
			mut(c)
			if err := c.Validate(); err == nil {
				t.Error("Validate accepted it")
			}
		})
	}
}

func TestConfigValidKnownGood(t *testing.T) {
	c := Defaults()
	if err := c.Validate(); err != nil {
		t.Fatalf("defaults invalid: %v", err)
	}
	if _, err := CompileRules(c.Rules); err != nil {
		t.Fatalf("default rules don't compile: %v", err)
	}
	for _, target := range []string{"", "http://app:3000", "https://example.com", "unix:///run/app.sock"} {
		if err := ValidateTarget(target); err != nil {
			t.Errorf("target %q rejected: %v", target, err)
		}
	}
}

func TestConfigClamps(t *testing.T) {
	c := Defaults()
	c.Protection.Difficulty = 0
	c.Protection.DefaultAction = "DENY"
	c.Protection.PassHours = 0
	c.Protection.ChallengeMinutes = 999
	c.Protection.MaxFailures = -5
	c.Server.IPSource = "bogus"
	c.Rules = []Rule{{Name: "r", Enabled: true, Action: ActionChallenge, Difficulty: 50}}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	p := c.Protection
	if p.Difficulty != 1 || p.DefaultAction != ActionChallenge || p.PassHours != 1 || p.ChallengeMinutes != 120 || p.MaxFailures != 0 {
		t.Errorf("protection not normalized: %+v", p)
	}
	if c.Server.IPSource != "remote" {
		t.Errorf("ip_source %q", c.Server.IPSource)
	}
	if c.Rules[0].Difficulty != 8 {
		t.Errorf("rule difficulty %d", c.Rules[0].Difficulty)
	}
	c.Protection.Difficulty = 99
	if err := c.Validate(); err != nil || c.Protection.Difficulty != 8 {
		t.Errorf("difficulty 99 -> %d (%v)", c.Protection.Difficulty, err)
	}
}

func TestManagerRejectsInvalidUpdate(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TAMAMO_TARGET", "")
	m, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	before := m.Get()
	err = m.Update(func(c *Config) error {
		c.Protection.Difficulty = 7
		c.Rules = append(c.Rules, Rule{Name: "bad", Enabled: true, Action: ActionBlock, Match: Match{UserAgents: []string{"re:(["}}})
		return nil
	})
	if err == nil {
		t.Fatal("invalid update accepted")
	}
	if m.Get() != before || m.Get().Protection.Difficulty == 7 || m.Stored().Protection.Difficulty == 7 {
		t.Error("invalid update changed the running config")
	}
	// A corrupt settings file fails to load instead of silently using defaults.
	bad := t.TempDir()
	if err := os.WriteFile(filepath.Join(bad, FileName), []byte("protection:\n  difficulty: [4\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(bad); err == nil {
		t.Error("corrupt tamamo.yaml loaded")
	}
	bad2 := t.TempDir()
	if err := os.WriteFile(filepath.Join(bad2, FileName), []byte("server:\n  target: ftp://x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(bad2); err == nil {
		t.Error("tamamo.yaml with an invalid target loaded")
	}
}

func TestIDsAreDerivedFromNames(t *testing.T) {
	c := Defaults()
	c.Rules = []Rule{
		{ID: "given", Name: "Block", Enabled: true, Action: ActionBlock},
		{Name: "Block", Enabled: true, Action: ActionAllow},
	}
	c.Sites = []Site{
		{ID: "given", Name: "My Blog", Hosts: []string{"blog.example.com"}},
		{ID: "given", Name: "My Blog!", Hosts: []string{"shop.example.com"}},
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if c.Rules[0].ID != "block" || c.Rules[1].ID != "block-2" {
		t.Errorf("rule ids %q %q", c.Rules[0].ID, c.Rules[1].ID)
	}
	if c.Sites[0].ID != "my-blog" || c.Sites[1].ID != "my-blog-2" {
		t.Errorf("site ids %q %q", c.Sites[0].ID, c.Sites[1].ID)
	}
	for _, st := range c.Sites {
		if st.ID == "given" {
			t.Error("a given site ID should be ignored")
		}
	}

	dup := Defaults()
	dup.Sites = []Site{{Name: "Shop", Hosts: []string{"a.example"}}, {Name: "shop", Hosts: []string{"b.example"}}}
	if err := dup.Validate(); err == nil || !strings.Contains(err.Error(), "two sites") {
		t.Errorf("site names not unique: %v", err)
	}
}

func TestLanguageKeepsAutoLanguage(t *testing.T) {
	c := Defaults()
	c.Page.Language = "auto"
	c.Page.AutoLanguage = false
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if c.Page.Language != "auto" || !c.Page.AutoLanguage {
		t.Errorf("auto: language %q, auto_language %v", c.Page.Language, c.Page.AutoLanguage)
	}

	// A chosen language wins over a stale auto_language flag.
	c = Defaults()
	c.Page.Language = "ru"
	c.Page.AutoLanguage = true
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if c.Page.Language != "ru" || c.Page.AutoLanguage {
		t.Errorf("ru: language %q, auto_language %v", c.Page.Language, c.Page.AutoLanguage)
	}
	if got := c.Page.PickLanguage("uk,en;q=0.5"); got != "ru" {
		t.Errorf("chosen language ignored: %q", got)
	}
}
