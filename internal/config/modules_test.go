package config

import (
	"strings"
	"testing"
)

func TestValidateModules(t *testing.T) {
	base := func(mods ...ModuleConfig) *Config {
		c := Defaults()
		c.Sites = []Site{{ID: "blog", Name: "Blog", Hosts: []string{"blog.example"}}}
		c.Modules = mods
		return c
	}
	ok := []ModuleConfig{
		{Name: "ratelimit", Type: "go", Enabled: true},
		{Name: "rl-api", Type: "GO", Module: "ratelimit", Enabled: true, Settings: map[string]string{"requests": "5", "action": "challenge"}},
		{Name: "mon", Type: "go", Module: "bypass-header", Enabled: true, Sites: []string{"default", "blog"},
			Settings: map[string]string{"header": "X-Mon", "value": "0123456789abcdef"}},
		{Name: "not-in-this-build", Type: "go", Enabled: false},
		{Name: "My webhook", Type: "webhook", URL: "https://hooks.example/check", Settings: map[string]string{"cache_seconds": "30"}},
		{Name: "banner_2", Type: "page", Enabled: true},
	}
	c := base(ok...)
	if err := c.Validate(); err != nil {
		t.Fatalf("valid modules rejected: %v", err)
	}
	wh := c.Modules[4]
	if wh.TimeoutMs != 500 || wh.OnError != "continue" || c.Modules[1].Type != "go" {
		t.Errorf("defaults not applied: %+v", wh)
	}
	if o, err := wh.WebhookOptions(); err != nil || o.CacheTTL.Seconds() != 30 {
		t.Errorf("webhook options %+v %v", o, err)
	}

	for want, m := range map[string]ModuleConfig{
		"needs a name":       {Type: "page"},
		"type must be":       {Name: "x", Type: "lua"},
		"no Go module":       {Name: "nope", Type: "go", Enabled: true},
		"at least 16":        {Name: "b", Type: "go", Module: "bypass-header", Enabled: true, Settings: map[string]string{"header": "X", "value": "short"}},
		"required":           {Name: "b", Type: "go", Module: "bypass-header", Enabled: true},
		"block or challenge": {Name: "r", Type: "go", Module: "ratelimit", Enabled: true, Settings: map[string]string{"action": "allow"}},
		"http://":            {Name: "w", Type: "webhook", URL: "file:///etc/passwd"},
		"timeout_ms":         {Name: "w", Type: "webhook", URL: "http://x", TimeoutMs: 20000},
		"on_error":           {Name: "w", Type: "webhook", URL: "http://x", OnError: "explode"},
		"cache_seconds":      {Name: "w", Type: "webhook", URL: "http://x", Settings: map[string]string{"cache_seconds": "-1"}},
		"no site":            {Name: "p", Type: "page", Sites: []string{"ghost"}},
		"folder name":        {Name: "Bad Name", Type: "page"},
		"folder name ":       {Name: "../etc", Type: "page"},
	} {
		err := base(m).Validate()
		if err == nil || !strings.Contains(err.Error(), strings.TrimSpace(want)) {
			t.Errorf("%+v: error %v, want %q", m, err, want)
		}
	}
	if err := base(ModuleConfig{Name: "a", Type: "page"}, ModuleConfig{Name: "a", Type: "webhook", URL: "http://x"}).Validate(); err == nil ||
		!strings.Contains(err.Error(), "unique") {
		t.Errorf("duplicate names: %v", err)
	}
}

func TestLabelsDefaults(t *testing.T) {
	c := Defaults()
	c.Page.Labels = Labels{Speed: "Fast"}
	c.Page.Translations["ru"] = PageTranslation{Title: "x"} // saved before labels existed
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if c.Page.Labels.Speed != "Fast" || c.Page.Labels.ChallengeUsed != DefaultLabels().ChallengeUsed {
		t.Errorf("main labels %+v", c.Page.Labels)
	}
	if c.Page.Translations["ru"].Labels.ChallengeUsed != DefaultTranslations()["ru"].Labels.ChallengeUsed {
		t.Error("built-in ru labels not filled in")
	}
	// Every label is set in every built-in language.
	for code, tr := range DefaultTranslations() {
		v := DefaultLabels()
		for _, l := range []Labels{v, tr.Labels} {
			if l.Over(Labels{}) != l {
				t.Fatal("Over changed labels")
			}
		}
		if tr.Labels.Over(Labels{}) != tr.Labels || tr.Labels.Difficulty == "" || tr.Labels.UpstreamDown == "" {
			t.Errorf("%s labels incomplete", code)
		}
	}
}
