package config

import (
	"errors"
	"strings"
	"testing"

	"github.com/foxgirlsorg/tamamo/module"
)

func init() {
	module.Register(module.Info{
		ID: "testmod",
		Settings: []module.Field{
			{Name: "token", Required: true, Default: ""},
			{Name: "limit", Type: module.Number, Default: "10", Min: 1, Max: 100},
			{Name: "mode", Type: module.Select, Default: "a", Options: []module.Option{{Value: "a"}, {Value: "b"}}},
		},
		New: func(ctx *module.Context) (module.Module, error) {
			if !ctx.Validating {
				return nil, errors.New("config validation must set Validating")
			}
			if ctx.Settings.String("token") == "bad" {
				return nil, errors.New("the token is bad")
			}
			return struct{}{}, nil
		},
	})
	// file_test.go and review_fixes_test.go use "testmod" without settings.
	module.Register(module.Info{ID: "plain", New: func(*module.Context) (module.Module, error) { return struct{}{}, nil }})
}

func TestValidateModules(t *testing.T) {
	base := func(mods ...ModuleConfig) *Config {
		c := Defaults()
		c.Sites = []Site{{ID: "blog", Name: "Blog", Hosts: []string{"blog.example"}}}
		c.Modules = mods
		return c
	}
	tok := map[string]string{"token": "x"}
	c := base(
		ModuleConfig{Name: "testmod", Enabled: true, Settings: tok},
		ModuleConfig{Name: "second", Module: "testmod", Enabled: true, Sites: []string{"default", "Blog", "blog"},
			Settings: map[string]string{"token": "x", "limit": "5", "mode": "b"}},
		ModuleConfig{Name: "not-in-this-build", Enabled: false},
		ModuleConfig{Module: "plain", Enabled: true, OnError: "BLOCK"},
	)
	if err := c.Validate(); err != nil {
		t.Fatalf("valid modules rejected: %v", err)
	}
	if m := c.Modules[1]; strings.Join(m.Sites, ",") != "default,blog" || m.OnError != "continue" {
		t.Errorf("sites/on_error not normalized: %+v", m)
	}
	if m := c.Modules[3]; m.Name != "plain" || m.Module != "" || m.OnError != "block" {
		t.Errorf("name should default to the module ID: %+v", m)
	}

	for name, tc := range map[string]struct {
		m    ModuleConfig
		want string
	}{
		"bad name":       {ModuleConfig{Name: "My Module", Module: "plain"}, "may only use"},
		"unknown module": {ModuleConfig{Name: "ghost", Enabled: true}, "compiled into this build"},
		"required":       {ModuleConfig{Name: "testmod", Enabled: true}, `"token" is required`},
		"number range":   {ModuleConfig{Name: "testmod", Enabled: true, Settings: map[string]string{"token": "x", "limit": "500"}}, "from 1 to 100"},
		"not a number":   {ModuleConfig{Name: "testmod", Enabled: true, Settings: map[string]string{"token": "x", "limit": "many"}}, "whole number"},
		"select":         {ModuleConfig{Name: "testmod", Enabled: true, Settings: map[string]string{"token": "x", "mode": "z"}}, "one of: a, b"},
		"error from New": {ModuleConfig{Name: "testmod", Enabled: true, Settings: map[string]string{"token": "bad"}}, "the token is bad"},
		"unknown site":   {ModuleConfig{Name: "plain", Sites: []string{"nowhere"}}, "no site called"},
		"on_error":       {ModuleConfig{Name: "plain", OnError: "explode"}, "on_error"},
	} {
		err := base(tc.m).Validate()
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: got %v, want an error containing %q", name, err, tc.want)
		}
	}
	if err := base(ModuleConfig{Name: "plain"}, ModuleConfig{Name: "plain"}).Validate(); err == nil || !strings.Contains(err.Error(), "unique") {
		t.Errorf("duplicate names: %v", err)
	}
}

func TestValidateChecks(t *testing.T) {
	c := Defaults()
	c.Protection.BypassHeaders = []BypassHeader{{Header: "x-monitor-token", Value: "0123456789abcdef"}}
	c.Protection.RateLimit = RateLimit{Enabled: true, Requests: 5_000_000, Action: "CHALLENGE"}
	c.Protection.Webhooks = []Webhook{{URL: " https://hooks.example/check "}}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	p := c.Protection
	if b := p.BypassHeaders[0]; b.Header != "X-Monitor-Token" || b.Name != "X-Monitor-Token" {
		t.Errorf("bypass header not normalized: %+v", b)
	}
	if rl := p.RateLimit; rl.Requests != 1_000_000 || rl.WindowSeconds != 60 || rl.Action != "challenge" || rl.IPv6Prefix != 64 || rl.MaxIPs != 100000 {
		t.Errorf("rate limit not normalized: %+v", rl)
	}
	if w := p.Webhooks[0]; w.Name != "webhook-1" || w.URL != "https://hooks.example/check" || w.TimeoutMs != 500 || w.OnError != "continue" {
		t.Errorf("webhook not normalized: %+v", w)
	}
	for name, mutate := range map[string]func(p *Protection){
		"short bypass value": func(p *Protection) { p.BypassHeaders = []BypassHeader{{Header: "X-A", Value: "short"}} },
		"bad bypass header":  func(p *Protection) { p.BypassHeaders = []BypassHeader{{Header: "X A", Value: "0123456789abcdef"}} },
		"rate limit action":  func(p *Protection) { p.RateLimit.Action = "allow" },
		"webhook URL":        func(p *Protection) { p.Webhooks = []Webhook{{Name: "w", URL: "ftp://x"}} },
		"webhook timeout":    func(p *Protection) { p.Webhooks = []Webhook{{Name: "w", URL: "http://x", TimeoutMs: 60000}} },
		"webhook cache":      func(p *Protection) { p.Webhooks = []Webhook{{Name: "w", URL: "http://x", CacheSeconds: 4000}} },
		"webhook on_error":   func(p *Protection) { p.Webhooks = []Webhook{{Name: "w", URL: "http://x", OnError: "allow"}} },
		"webhook names": func(p *Protection) {
			p.Webhooks = []Webhook{{Name: "w", URL: "http://x"}, {Name: "W", URL: "http://y"}}
		},
	} {
		c := Defaults()
		mutate(&c.Protection)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestChecksRoundTripAndSiteOverride(t *testing.T) {
	c := Defaults()
	c.Protection.BypassHeaders = []BypassHeader{{Name: "Monitor", Header: "X-Monitor-Token", Value: "0123456789abcdef"}}
	c.Protection.Webhooks = []Webhook{{Name: "Reputation", Enabled: true, URL: "http://checker:9000/check", CacheSeconds: 30}}
	own := c.Protection
	own.RateLimit.Enabled = true
	own.RateLimit.Requests = 30
	c.Sites = []Site{{Name: "Shop", Hosts: []string{"shop.example.com"}, OwnProtection: true, Protection: own}}
	c = mustValid(t, c)
	back, y := roundTrip(t, c)
	if asJSON(c) != asJSON(back) {
		t.Fatalf("round trip changed the config:\n%s", y)
	}
	// The site lists only what it changes.
	site := y[strings.Index(y, "- name: Shop"):]
	site = site[:strings.Index(site, "modules:")]
	if !strings.Contains(site, "requests: 30") || strings.Contains(site, "webhooks") || strings.Contains(site, "window_seconds") {
		t.Errorf("the site should only list the rate limit fields it changes:\n%s", site)
	}
	if !strings.Contains(y, "# Limit how many requests one IP address may make.") {
		t.Errorf("the rate limit has no comment in the file:\n%s", y)
	}
}

func TestLegacyModulesAreMigrated(t *testing.T) {
	c, err := ParseConfigYAML([]byte(`
sites:
  - name: Blog
    hosts: [blog.example.com]
  - name: Shop
    hosts: [shop.example.com]
modules:
  - name: Uptime monitor
    enabled: true
    type: go
    module: bypass-header
    settings: {header: X-Monitor-Token, value: a-long-random-secret}
  - name: ratelimit
    enabled: true
    type: go
    sites: [Shop]
    settings: {requests: "30", action: challenge}
  - name: Reputation
    enabled: true
    type: webhook
    url: http://checker:9000/check
    timeout_ms: 800
    on_error: block
    settings: {cache_seconds: "60", send_cookies: "true"}
  - name: banner
    enabled: true
    type: page
  - name: My Check
    enabled: false
    type: go
    module: testmod
    settings: {token: abc}
  - name: plain
    enabled: true
`))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	p := c.Protection
	if len(p.BypassHeaders) != 1 || p.BypassHeaders[0].Name != "Uptime monitor" || p.BypassHeaders[0].Header != "X-Monitor-Token" {
		t.Errorf("bypass header: %+v", p.BypassHeaders)
	}
	if len(p.Webhooks) != 1 {
		t.Fatalf("webhooks: %+v", p.Webhooks)
	}
	if w := p.Webhooks[0]; w.Name != "Reputation" || !w.Enabled || w.TimeoutMs != 800 || w.OnError != "block" || w.CacheSeconds != 60 || !w.SendCookies {
		t.Errorf("webhook: %+v", w)
	}
	if p.RateLimit.Enabled {
		t.Errorf("the rate limit was limited to Shop; the global one must stay off")
	}
	blog, shop := c.Sites[0], c.Sites[1]
	if blog.OwnProtection {
		t.Errorf("Blog should still follow the global protection")
	}
	if !shop.OwnProtection || !shop.Protection.RateLimit.Enabled || shop.Protection.RateLimit.Requests != 30 || shop.Protection.RateLimit.Action != "challenge" {
		t.Errorf("Shop rate limit: %+v", shop.Protection.RateLimit)
	}
	if len(shop.Protection.Webhooks) != 1 || len(shop.Protection.BypassHeaders) != 1 {
		t.Errorf("Shop should keep the global bypass header and webhook: %+v", shop.Protection)
	}
	if len(c.Modules) != 2 {
		t.Fatalf("modules: %+v", c.Modules)
	}
	if m := c.Modules[0]; m.Name != "my-check" || m.Module != "testmod" || m.Enabled || m.Settings["token"] != "abc" {
		t.Errorf("migrated module: %+v", m)
	}
	// What is written back is the new format only.
	y, err := MarshalConfigYAML(c)
	if err != nil {
		t.Fatal(err)
	}
	for _, gone := range []string{"type:", "timeout_ms: 800\n    on_error: block\n    settings", "bypass-header"} {
		if strings.Contains(string(y), gone) {
			t.Errorf("the file still has %q:\n%s", gone, y)
		}
	}
	if _, err := ParseConfigYAML(y); err != nil {
		t.Errorf("the migrated file doesn't parse: %v", err)
	}
	// Typos in a module entry are still caught.
	if _, err := ParseConfigYAML([]byte("modules:\n  - name: plain\n    enabld: true\n")); err == nil || !strings.Contains(err.Error(), "enabled") {
		t.Errorf("typo not caught: %v", err)
	}
}
