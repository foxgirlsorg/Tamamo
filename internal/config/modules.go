package config

import (
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/foxgirlsorg/tamamo/module"
)

// ModuleConfig switches one module on and configures it. Modules are Go
// modules compiled into the binary (see the module package).
type ModuleConfig struct {
	// Name identifies this entry: a-z, 0-9 and dashes. It appears in logs, in
	// the module's URLs (/.tamamo/x/<name>/, /api/x/<name>/) and names its
	// data folder.
	Name string `json:"name" yaml:"name"`
	// Module is the ID the module registered under, when it differs from
	// Name, so one module can be used twice with different settings (e.g.
	// name "geo-shop", module "geo").
	Module  string `json:"module,omitempty" yaml:"module,omitempty"`
	Enabled bool   `json:"enabled" yaml:"enabled"`
	// Sites limits the module to these sites, by name or ID ("default" for
	// the default site). Empty = every site.
	Sites []string `json:"sites" yaml:"sites"`
	// OnError says what to do with a request when the module's check fails:
	// "continue" (ignore it), "challenge" or "block".
	OnError string `json:"on_error" yaml:"on_error"`
	// Settings are the module's own options, described by the module.
	Settings map[string]string `json:"settings" yaml:"settings"`
}

// ModuleID returns the registered module this entry runs.
func (m *ModuleConfig) ModuleID() string {
	if m.Module != "" {
		return m.Module
	}
	return m.Name
}

// AppliesTo reports whether the module is switched on for site ID siteID.
func (m *ModuleConfig) AppliesTo(siteID string) bool {
	if !m.Enabled {
		return false
	}
	return len(m.Sites) == 0 || slices.Contains(m.Sites, siteID)
}

func validateModules(c *Config) error {
	if c.Modules == nil {
		c.Modules = []ModuleConfig{}
	}
	// Modules name their sites; the site ID (derived from the name) and the
	// name itself both work.
	sites := map[string]string{DefaultSiteID: DefaultSiteID}
	for _, s := range c.Sites {
		sites[s.ID] = s.ID
		sites[strings.ToLower(s.Name)] = s.ID
	}
	names := map[string]bool{}
	for i := range c.Modules {
		m := &c.Modules[i]
		m.Name = strings.TrimSpace(m.Name)
		m.Module = strings.TrimSpace(m.Module)
		if m.Name == "" {
			m.Name = m.Module
		}
		if m.Name == "" {
			return fmt.Errorf("module %d needs a name", i+1)
		}
		if !module.ValidID(m.Name) {
			return fmt.Errorf("module name %q may only use a-z, 0-9 and dashes (at most 64, starting with a letter or digit)", m.Name)
		}
		if names[m.Name] {
			return fmt.Errorf("two modules are called %q; module names must be unique", m.Name)
		}
		names[m.Name] = true
		if m.Module == m.Name {
			m.Module = ""
		}
		if m.Settings == nil {
			m.Settings = map[string]string{}
		}
		cleanSites := []string{}
		for _, s := range m.Sites {
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			id, ok := sites[s]
			if !ok {
				id, ok = sites[strings.ToLower(s)]
			}
			if !ok {
				return fmt.Errorf("module %q: there is no site called %q", m.Name, s)
			}
			if !slices.Contains(cleanSites, id) {
				cleanSites = append(cleanSites, id)
			}
		}
		m.Sites = cleanSites
		m.OnError = strings.ToLower(strings.TrimSpace(m.OnError))
		if m.OnError == "" {
			m.OnError = "continue"
		}
		if !oneOf(m.OnError, "continue", ActionChallenge, ActionBlock) {
			return fmt.Errorf("module %q: on_error must be continue, challenge or block", m.Name)
		}
		if !m.Enabled {
			// A switched-off module may belong to another build.
			continue
		}
		info, ok := module.Lookup(m.ModuleID())
		if !ok {
			return fmt.Errorf("module %q: no module with the ID %q is compiled into this build", m.Name, m.ModuleID())
		}
		ctx := module.NewContext(m.Name, m.Settings, m.Sites, "")
		ctx.Validating = true
		if _, err := info.Create(ctx); err != nil {
			return fmt.Errorf("module %q: %v", m.Name, err)
		}
	}
	return nil
}

// ---- reading the modules section ---------------------------------------------

// legacyModule is a modules entry as written before rate limits, bypass
// headers and webhooks became protection settings and page modules were
// replaced by Go modules.
type legacyModule struct {
	Name      string            `yaml:"name"`
	Enabled   bool              `yaml:"enabled"`
	Type      string            `yaml:"type"`
	Module    string            `yaml:"module"`
	Sites     []string          `yaml:"sites"`
	URL       string            `yaml:"url"`
	TimeoutMs int               `yaml:"timeout_ms"`
	OnError   string            `yaml:"on_error"`
	Settings  map[string]string `yaml:"settings"`
}

// scopedChange is a migrated entry: a change to a protection section, for
// the listed sites (none = the global protection).
type scopedChange struct {
	sites []string
	apply func(p *Protection)
	what  string
}

// parseModules reads the modules section, moving entries in the old format
// to where they live now. The returned changes are for sites, which are
// read later.
func parseModules(cfg *Config, n *yaml.Node) ([]scopedChange, error) {
	cfg.Modules = []ModuleConfig{}
	if isNull(n) {
		return nil, nil
	}
	if n.Kind != yaml.SequenceNode {
		return nil, errAt(n, "modules must be a list, each module starting with \"- name: ...\"")
	}
	var pending []scopedChange
	for _, c := range n.Content {
		c = deref(c)
		if c.Kind != yaml.MappingNode {
			return nil, errAt(c, "each module must be a group of settings starting with \"- name: ...\"")
		}
		if lookup(c, "type") == nil && lookup(c, "url") == nil && lookup(c, "timeout_ms") == nil {
			var m ModuleConfig
			if err := decodeInto(c, &m, "modules"); err != nil {
				return nil, err
			}
			cfg.Modules = append(cfg.Modules, m)
			continue
		}
		var lm legacyModule
		if err := decodeInto(c, &lm, "modules"); err != nil {
			return nil, err
		}
		change, err := migrateModule(cfg, &lm)
		if err != nil {
			return nil, errAt(c, "%v", err)
		}
		if change == nil {
			continue
		}
		if len(lm.Sites) == 0 {
			change.apply(&cfg.Protection)
		} else {
			pending = append(pending, *change)
		}
	}
	return pending, nil
}

// migrateModule turns an old-format entry into today's settings. It returns
// a change to a protection section, or nil when the entry became a module
// entry or was dropped.
func migrateModule(cfg *Config, lm *legacyModule) (*scopedChange, error) {
	name := strings.TrimSpace(lm.Name)
	id := strings.TrimSpace(lm.Module)
	if id == "" {
		id = name
	}
	switch strings.ToLower(strings.TrimSpace(lm.Type)) {
	case "webhook":
		cache, _ := strconv.Atoi(strings.TrimSpace(lm.Settings["cache_seconds"]))
		wh := Webhook{
			Name: name, Enabled: lm.Enabled, URL: lm.URL, TimeoutMs: lm.TimeoutMs, OnError: lm.OnError,
			CacheSeconds: cache, SendCookies: module.Settings(lm.Settings).Bool("send_cookies"),
		}
		slog.Warn("tamamo.yaml: webhook module moved to protection.webhooks", "name", name)
		return &scopedChange{sites: lm.Sites, what: "webhook " + name, apply: func(p *Protection) {
			p.Webhooks = append(slices.Clone(p.Webhooks), wh)
		}}, nil
	case "page":
		slog.Warn("tamamo.yaml: page modules (folders of HTML/CSS) are no longer supported and this entry was removed; "+
			"use page.custom_css or a Go module that extends the page", "name", name)
		return nil, nil
	case "go", "":
	default:
		return nil, fmt.Errorf("module %q: unknown type %q", name, lm.Type)
	}
	s := module.Settings(lm.Settings)
	switch id {
	case "ratelimit":
		rl := RateLimit{
			Enabled: lm.Enabled, Requests: s.Int("requests", 120), WindowSeconds: s.Int("window_seconds", 60),
			Action: s.String("action"), IPv6Prefix: s.Int("ipv6_prefix", 64), MaxIPs: s.Int("max_ips", 100000),
		}
		slog.Warn("tamamo.yaml: ratelimit module moved to protection.rate_limit", "name", name)
		return &scopedChange{sites: lm.Sites, what: "rate limit " + name, apply: func(p *Protection) { p.RateLimit = rl }}, nil
	case "bypass-header":
		if !lm.Enabled {
			slog.Warn("tamamo.yaml: switched-off bypass-header module removed", "name", name)
			return nil, nil
		}
		bh := BypassHeader{Name: name, Header: s.String("header"), Value: lm.Settings["value"]}
		slog.Warn("tamamo.yaml: bypass-header module moved to protection.bypass_headers", "name", name)
		return &scopedChange{sites: lm.Sites, what: "bypass header " + name, apply: func(p *Protection) {
			p.BypassHeaders = append(slices.Clone(p.BypassHeaders), bh)
		}}, nil
	}
	m := ModuleConfig{Name: name, Module: lm.Module, Enabled: lm.Enabled, Sites: lm.Sites, OnError: lm.OnError, Settings: lm.Settings}
	if !module.ValidID(m.Name) {
		// Names used to be free text; they are IDs now.
		m.Name = SlugID(name, id)
		if !module.ValidID(m.Name) {
			m.Name = id
		}
		if m.Module == "" && m.Name != id {
			m.Module = id
		}
	}
	cfg.Modules = append(cfg.Modules, m)
	return nil, nil
}

// applyScoped applies migrated entries that were limited to some sites. A
// listed site gets protection settings of its own; "default" changes the
// global protection, which sites without their own settings follow.
func applyScoped(cfg *Config, sites []Site, pending []scopedChange) {
	for _, ch := range pending {
		for _, ref := range ch.sites {
			ref = strings.ToLower(strings.TrimSpace(ref))
			if ref == DefaultSiteID {
				ch.apply(&cfg.Protection)
				slog.Warn("tamamo.yaml: a check that was limited to the default site now applies to every site without protection settings of its own", "check", ch.what)
				continue
			}
			found := false
			for i := range sites {
				st := &sites[i]
				if strings.ToLower(st.Name) != ref && SlugID(st.Name, "site") != ref {
					continue
				}
				if !st.OwnProtection {
					st.OwnProtection = true
					st.Protection = cfg.Protection
				}
				ch.apply(&st.Protection)
				found = true
			}
			if !found {
				slog.Warn("tamamo.yaml: a migrated check names a site that doesn't exist; skipped for it", "check", ch.what, "site", ref)
			}
		}
	}
}
