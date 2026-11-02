package config

import (
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/tamamo/tamamo/internal/modules"
)

// Module types.
const (
	ModuleGo      = "go"
	ModuleWebhook = "webhook"
	ModulePage    = "page"
)

// ModuleConfig turns one module on and configures it. The module agent owns
// this file's validation logic; the struct is the shared contract.
type ModuleConfig struct {
	// Name identifies the module: for "page" modules it is also the folder
	// name under <data>/modules/; for "go" modules the registered name
	// (unless Module is set).
	Name    string `json:"name" yaml:"name"`
	Enabled bool   `json:"enabled" yaml:"enabled"`
	// Type is "webhook" (Tamamo asks an HTTP endpoint about each request),
	// "page" (files added to the checking page) or "go" (compiled in).
	Type string `json:"type" yaml:"type"`
	// Module is, for "go" modules, the registered module to run when it
	// differs from Name, so one module can be used twice with different
	// settings (e.g. name "ratelimit-api", module "ratelimit").
	Module string `json:"module,omitempty" yaml:"module,omitempty"`
	// Sites limits the module to these sites, by name or ID ("default" for
	// the default site). Empty = every site.
	Sites []string `json:"sites" yaml:"sites"`
	// Webhook settings.
	URL       string `json:"url" yaml:"url"`
	TimeoutMs int    `json:"timeout_ms" yaml:"timeout_ms"`
	// OnError says what to do when the module fails or times out:
	// "continue" (ignore it), "challenge" or "block".
	OnError string `json:"on_error" yaml:"on_error"`
	// Settings are free-form options passed to the module. Webhooks read
	// "cache_seconds" (0-3600) and "send_cookies" (true/false).
	Settings map[string]string `json:"settings" yaml:"settings"`
}

// GoModule returns the registered module a "go" module config runs.
func (m *ModuleConfig) GoModule() string {
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
	if len(m.Sites) == 0 {
		return true
	}
	for _, s := range m.Sites {
		if s == siteID {
			return true
		}
	}
	return false
}

// WebhookOptions turns a validated webhook module config into options.
func (m *ModuleConfig) WebhookOptions() (modules.WebhookOptions, error) {
	o := modules.WebhookOptions{URL: m.URL}
	if m.TimeoutMs > 0 {
		o.Timeout = msDuration(m.TimeoutMs)
	}
	secs, err := modules.IntSetting(m.Settings, "cache_seconds", 0, 0, 3600)
	if err != nil {
		return o, err
	}
	o.CacheTTL = msDuration(secs * 1000)
	switch strings.ToLower(strings.TrimSpace(m.Settings["send_cookies"])) {
	case "", "false", "0", "no", "off":
	case "true", "1", "yes", "on":
		o.SendCookies = true
	default:
		return o, fmt.Errorf("setting \"send_cookies\" must be true or false")
	}
	return o, nil
}

func msDuration(ms int) time.Duration { return time.Duration(ms) * time.Millisecond }

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
		m.Type = strings.ToLower(strings.TrimSpace(m.Type))
		m.Module = strings.TrimSpace(m.Module)
		if m.Name == "" {
			return fmt.Errorf("module %d needs a name", i+1)
		}
		if len(m.Name) > 64 || strings.IndexFunc(m.Name, unicode.IsControl) >= 0 {
			return fmt.Errorf("module name %q is too long or has control characters", m.Name)
		}
		if names[m.Name] {
			return fmt.Errorf("two modules are called %q; module names must be unique", m.Name)
		}
		names[m.Name] = true
		if m.Settings == nil {
			m.Settings = map[string]string{}
		}
		var cleanSites []string
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
			s = id
			cleanSites = append(cleanSites, s)
		}
		if cleanSites == nil {
			cleanSites = []string{}
		}
		m.Sites = cleanSites
		m.OnError = strings.ToLower(strings.TrimSpace(m.OnError))
		if m.OnError == "" {
			m.OnError = "continue"
		}
		if !oneOf(m.OnError, "continue", ActionChallenge, ActionBlock) {
			return fmt.Errorf("module %q: on_error must be continue, challenge or block", m.Name)
		}

		switch m.Type {
		case ModuleGo:
			if !m.Enabled {
				// A switched-off module may belong to another build.
				continue
			}
			if _, ok := modules.Lookup(m.GoModule()); !ok {
				return fmt.Errorf("module %q: no Go module named %q is compiled into this build", m.Name, m.GoModule())
			}
			if _, err := modules.New(m.GoModule(), m.Settings); err != nil {
				return fmt.Errorf("module %q: %v", m.Name, err)
			}
		case ModuleWebhook:
			m.URL = strings.TrimSpace(m.URL)
			if err := modules.CheckWebhookURL(m.URL); err != nil {
				return fmt.Errorf("module %q: %v", m.Name, err)
			}
			if m.TimeoutMs == 0 {
				m.TimeoutMs = 500
			}
			if m.TimeoutMs < 1 || m.TimeoutMs > 10000 {
				return fmt.Errorf("module %q: timeout_ms must be from 1 to 10000", m.Name)
			}
			if _, err := m.WebhookOptions(); err != nil {
				return fmt.Errorf("module %q: %v", m.Name, err)
			}
		case ModulePage:
			if !modules.ValidPageName(m.Name) {
				return fmt.Errorf("page module %q: the name is a folder name and may only use a-z, 0-9, - and _ (at most 64, starting with a letter or digit)", m.Name)
			}
		default:
			return fmt.Errorf("module %q: type must be go, webhook or page", m.Name)
		}
	}
	return nil
}
