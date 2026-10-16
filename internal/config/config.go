// Package config holds Tamamo's settings: their defaults, validation,
// persistence to disk and environment-variable overrides.
package config

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Actions a rule (or the default) can take.
const (
	ActionAllow     = "allow"
	ActionChallenge = "challenge"
	ActionBlock     = "block"
)

// DefaultSiteID identifies the built-in site that serves every host no other
// site claims. Its settings are the top-level Protection, Rules and Page.
const DefaultSiteID = "default"

type Config struct {
	Server ServerConfig `json:"server" yaml:"server"`
	// Protection, Rules and Page are the global settings: they apply to the
	// default site and to every site that doesn't override them.
	Protection Protection  `json:"protection" yaml:"protection"`
	Rules      []Rule      `json:"rules" yaml:"rules"`
	Page       Page        `json:"page" yaml:"page"`
	Sites      []Site      `json:"sites" yaml:"sites"`
	Admin      AdminConfig `json:"admin" yaml:"admin"`
	Stats      StatsConfig `json:"stats" yaml:"stats"`
	// Secret signs challenges and visitor passes. Never sent to the web UI.
	Secret string `json:"secret,omitempty" yaml:"-"`
}

// Site is one protected website, picked by the request's Host header.
// Each section is either its own (Own* = true) or follows the global one.
type Site struct {
	ID    string   `json:"id" yaml:"-"` // derived from Name, see SlugID
	Name  string   `json:"name" yaml:"name"`
	Hosts []string `json:"hosts" yaml:"hosts"` // "blog.example.com", "*.example.com"
	// Target is where verified traffic for this site goes. Empty = server.target.
	// Not needed when the site runs behind nginx auth_request.
	Target string `json:"target" yaml:"target"`

	OwnProtection bool       `json:"own_protection" yaml:"-"`
	Protection    Protection `json:"protection" yaml:"protection"`
	OwnRules      bool       `json:"own_rules" yaml:"-"`
	Rules         []Rule     `json:"rules" yaml:"rules"`
	OwnPage       bool       `json:"own_page" yaml:"-"`
	Page          Page       `json:"page" yaml:"page"`
}

type ServerConfig struct {
	Listen             string   `json:"listen" yaml:"listen"`
	Target             string   `json:"target" yaml:"target"`
	IPSource           string   `json:"ip_source" yaml:"ip_source"`
	TrustedProxies     []string `json:"trusted_proxies" yaml:"trusted_proxies"`
	PreserveHost       bool     `json:"preserve_host" yaml:"preserve_host"`
	InsecureSkipVerify bool     `json:"insecure_skip_verify" yaml:"insecure_skip_verify"`
}

type Protection struct {
	Enabled          bool   `json:"enabled" yaml:"enabled"`
	Difficulty       int    `json:"difficulty" yaml:"difficulty"`
	DefaultAction    string `json:"default_action" yaml:"default_action"`
	PassHours        int    `json:"pass_hours" yaml:"pass_hours"`
	ChallengeMinutes int    `json:"challenge_minutes" yaml:"challenge_minutes"`
	BindIP           bool   `json:"bind_ip" yaml:"bind_ip"`
	BindUserAgent    bool   `json:"bind_user_agent" yaml:"bind_user_agent"`
	CookieName       string `json:"cookie_name" yaml:"cookie_name"`
	CookieDomain     string `json:"cookie_domain" yaml:"cookie_domain"`
	MaxFailures      int    `json:"max_failures_per_minute" yaml:"max_failures_per_minute"`
}

type HeaderMatch struct {
	Name    string `json:"name" yaml:"name"`
	Pattern string `json:"pattern" yaml:"pattern"`
}

type Match struct {
	Paths      []string      `json:"paths" yaml:"paths"`
	UserAgents []string      `json:"user_agents" yaml:"user_agents"`
	IPs        []string      `json:"ips" yaml:"ips"`
	Methods    []string      `json:"methods" yaml:"methods"`
	Hosts      []string      `json:"hosts" yaml:"hosts"`
	Headers    []HeaderMatch `json:"headers" yaml:"headers"`
}

type Rule struct {
	ID         string `json:"id" yaml:"-"` // derived from Name, see SlugID
	Name       string `json:"name" yaml:"name"`
	Enabled    bool   `json:"enabled" yaml:"enabled"`
	Action     string `json:"action" yaml:"action"`
	Difficulty int    `json:"difficulty" yaml:"difficulty"`
	Match      Match  `json:"match" yaml:"match"`
	Note       string `json:"note" yaml:"note"`
}

type StateText struct {
	Heading string `json:"heading" yaml:"heading"`
	Message string `json:"message" yaml:"message"`
}

type PageTexts struct {
	Checking StateText `json:"checking" yaml:"checking"`
	Success  StateText `json:"success" yaml:"success"`
	Denied   StateText `json:"denied" yaml:"denied"`
	Error    StateText `json:"error" yaml:"error"`
}

type Palette struct {
	Background string `json:"background" yaml:"background"`
	Surface    string `json:"surface" yaml:"surface"`
	Text       string `json:"text" yaml:"text"`
	Muted      string `json:"muted" yaml:"muted"`
	Accent     string `json:"accent" yaml:"accent"`
	AccentText string `json:"accent_text" yaml:"accent_text"`
	Border     string `json:"border" yaml:"border"`
	Success    string `json:"success" yaml:"success"`
	Danger     string `json:"danger" yaml:"danger"`
}

type Page struct {
	Title         string    `json:"title" yaml:"title"`
	Lang          string    `json:"lang" yaml:"lang"`
	Texts         PageTexts `json:"texts" yaml:"texts"`
	RetryLabel    string    `json:"retry_label" yaml:"retry_label"`
	ContinueLabel string    `json:"continue_label" yaml:"continue_label"`
	NoScript      string    `json:"noscript" yaml:"noscript"`
	FooterText    string    `json:"footer_text" yaml:"footer_text"`

	ThemeMode string  `json:"theme_mode" yaml:"theme_mode"` // light | dark | auto
	Light     Palette `json:"light" yaml:"light"`
	Dark      Palette `json:"dark" yaml:"dark"`

	Font          string `json:"font" yaml:"font"` // system | serif | rounded | mono | custom
	CustomFont    string `json:"custom_font" yaml:"custom_font"`
	FontScale     int    `json:"font_scale" yaml:"font_scale"`
	HeadingWeight int    `json:"heading_weight" yaml:"heading_weight"`
	Align         string `json:"align" yaml:"align"` // left | center

	Layout     string `json:"layout" yaml:"layout"` // card | split | minimal
	CardWidth  int    `json:"card_width" yaml:"card_width"`
	Radius     int    `json:"radius" yaml:"radius"`
	CardBorder bool   `json:"card_border" yaml:"card_border"`
	CardShadow bool   `json:"card_shadow" yaml:"card_shadow"`

	MascotShow      bool   `json:"mascot_show" yaml:"mascot_show"`
	MascotPosition  string `json:"mascot_position" yaml:"mascot_position"` // top | left | right | bottom
	MascotSize      int    `json:"mascot_size" yaml:"mascot_size"`
	MascotAnimation string `json:"mascot_animation" yaml:"mascot_animation"` // none | float | bounce | wiggle
	MascotMirror    bool   `json:"mascot_mirror" yaml:"mascot_mirror"`

	Background     string `json:"background" yaml:"background"` // solid | dots | grid | stripes | image
	BackgroundBlur int    `json:"background_blur" yaml:"background_blur"`
	BackgroundDim  int    `json:"background_dim" yaml:"background_dim"`

	Progress       string `json:"progress" yaml:"progress"` // bar | ring | dots | spinner | none
	ShowDifficulty bool   `json:"show_difficulty" yaml:"show_difficulty"`
	ShowHashRate   bool   `json:"show_hash_rate" yaml:"show_hash_rate"`
	ShowElapsed    bool   `json:"show_elapsed" yaml:"show_elapsed"`
	ShowPercent    bool   `json:"show_percent" yaml:"show_percent"`

	MinDisplayMs   int  `json:"min_display_ms" yaml:"min_display_ms"`
	SuccessDelayMs int  `json:"success_delay_ms" yaml:"success_delay_ms"`
	AutoRedirect   bool `json:"auto_redirect" yaml:"auto_redirect"`
	Animations     bool `json:"animations" yaml:"animations"`

	CreditAlign string `json:"credit_align" yaml:"credit_align"` // left | center | right
	CustomCSS   string `json:"custom_css" yaml:"custom_css"`

	// Language picks which language the page is shown in: "auto" uses the
	// visitor's browser language when a translation exists, a code (Lang or
	// a key of Translations) always shows that one.
	Language string `json:"language" yaml:"language"`
	// AutoLanguage mirrors Language == "auto" for older web UI versions.
	AutoLanguage bool         `json:"auto_language" yaml:"-"`
	Translations Translations `json:"translations" yaml:"translations"`

	// Labels are the page's smaller words: stat labels, units and the
	// messages of the solver and the server (see i18n.go).
	Labels Labels `json:"labels" yaml:"labels"`
}

// PageTranslation holds the checking page's words in one more language.
// Empty fields fall back to the page's main texts.
type PageTranslation struct {
	Title         string    `json:"title" yaml:"title"`
	Texts         PageTexts `json:"texts" yaml:"texts"`
	RetryLabel    string    `json:"retry_label" yaml:"retry_label"`
	ContinueLabel string    `json:"continue_label" yaml:"continue_label"`
	NoScript      string    `json:"noscript" yaml:"noscript"`
	FooterText    string    `json:"footer_text" yaml:"footer_text"`
	Labels        Labels    `json:"labels" yaml:"labels"`
}

type AdminConfig struct {
	// Enabled reports whether the admin API runs. It is not a setting: only
	// the TAMAMO_ENABLE_API=true environment variable turns the API on.
	Enabled      bool   `json:"enabled" yaml:"-"`
	Listen       string `json:"listen" yaml:"listen"`
	Username     string `json:"username" yaml:"username"`
	PasswordHash string `json:"password_hash,omitempty" yaml:"password_hash,omitempty"`
	SessionHours int    `json:"session_hours" yaml:"session_hours"`
}

type StatsConfig struct {
	Enabled      bool `json:"enabled" yaml:"enabled"`
	StoreIPs     bool `json:"store_ips" yaml:"store_ips"`
	RecentEvents int  `json:"recent_events" yaml:"recent_events"`
}

// Clone returns a deep copy.
func (c *Config) Clone() *Config {
	b, _ := json.Marshal(c)
	out := &Config{}
	_ = json.Unmarshal(b, out)
	return out
}

// Public returns a copy safe to hand to the web UI (no secret, no hash).
func (c *Config) Public() *Config {
	out := c.Clone()
	out.Secret = ""
	out.Admin.PasswordHash = ""
	return out
}

var (
	hexColor   = regexp.MustCompile(`^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{4}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})$`)
	fontFamily = regexp.MustCompile(`^[a-zA-Z0-9 ,'"\-]*$`)
	langTag    = regexp.MustCompile(`^[a-zA-Z]{2,3}(-[a-zA-Z0-9]{2,8})?$`)
	cookieName = regexp.MustCompile(`^[a-zA-Z0-9_\-]{1,64}$`)
)

func oneOf(v string, opts ...string) bool {
	for _, o := range opts {
		if v == o {
			return true
		}
	}
	return false
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// ValidateTarget checks an upstream address: http(s)://host[:port] or unix:///path.
func ValidateTarget(t string) error {
	if t == "" {
		return nil
	}
	if strings.HasPrefix(t, "unix://") {
		if len(t) <= len("unix://") {
			return errors.New("unix socket path is empty")
		}
		return nil
	}
	u, err := url.Parse(t)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("%q must look like http://app:3000 or https://example.com", t)
	}
	return nil
}

func validatePalette(name string, p *Palette) error {
	for field, v := range map[string]string{
		"background": p.Background, "surface": p.Surface, "text": p.Text, "muted": p.Muted,
		"accent": p.Accent, "accent text": p.AccentText, "border": p.Border,
		"success": p.Success, "danger": p.Danger,
	} {
		if !hexColor.MatchString(v) {
			return fmt.Errorf("%s color %q (%s) must be a hex color like #de6161", name, field, v)
		}
	}
	return nil
}

// Validate normalizes ranges and reports the first setting that cannot be used.
func (c *Config) Validate() error {
	s := &c.Server
	if s.Listen == "" {
		s.Listen = ":8923"
	}
	if err := ValidateTarget(s.Target); err != nil {
		return fmt.Errorf("upstream: %w", err)
	}
	if !oneOf(s.IPSource, "remote", "x-forwarded-for", "x-real-ip", "cf-connecting-ip") {
		s.IPSource = "remote"
	}
	for _, p := range s.TrustedProxies {
		if _, err := ParsePrefix(p); err != nil {
			return fmt.Errorf("trusted proxy %q is not an IP or CIDR range", p)
		}
	}
	if err := validateProtection(&c.Protection); err != nil {
		return err
	}
	if err := validateRules(c.Rules); err != nil {
		return err
	}
	if err := validatePage(&c.Page); err != nil {
		return err
	}
	if err := c.validateSites(); err != nil {
		return err
	}

	a := &c.Admin
	if a.Listen == "" {
		a.Listen = ":8081"
	}
	a.SessionHours = clamp(a.SessionHours, 1, 24*90)

	c.Stats.RecentEvents = clamp(c.Stats.RecentEvents, 10, 2000)
	return nil
}

// validateSites gives every site an ID and a name, checks its host patterns
// and target, and fills the sections it doesn't override with copies of the
// global ones (so switching "own settings" on starts from the current globals).
func (c *Config) validateSites() error {
	seen := map[string]string{}
	ids := map[string]bool{}
	ids[DefaultSiteID] = true
	names := map[string]bool{}
	for i := range c.Sites {
		st := &c.Sites[i]
		st.Name = strings.TrimSpace(st.Name)
		var hosts []string
		for _, h := range st.Hosts {
			h = strings.ToLower(strings.TrimSpace(h))
			if h == "" {
				continue
			}
			if _, err := compilePattern(h, true, true); err != nil {
				return fmt.Errorf("site %q: host %q: %v", st.Name, h, err)
			}
			if other, dup := seen[h]; dup {
				return fmt.Errorf("host %q is used by two sites (%s and %s)", h, other, st.Name)
			}
			seen[h] = st.Name
			hosts = append(hosts, h)
		}
		st.Hosts = hosts
		if st.Name == "" {
			if len(hosts) > 0 {
				st.Name = hosts[0]
			} else {
				st.Name = fmt.Sprintf("Site %d", i+1)
			}
		}
		if len(hosts) == 0 {
			return fmt.Errorf("site %q needs at least one host name", st.Name)
		}
		if names[strings.ToLower(st.Name)] {
			return fmt.Errorf("two sites are called %q; give every site its own name", st.Name)
		}
		names[strings.ToLower(st.Name)] = true
		// The ID is derived from the name, so the file never needs one.
		st.ID = uniqueID(SlugID(st.Name, "site"), ids)
		if err := ValidateTarget(st.Target); err != nil {
			return fmt.Errorf("site %q: %w", st.Name, err)
		}
		if st.OwnProtection {
			if err := validateProtection(&st.Protection); err != nil {
				return fmt.Errorf("site %q: %w", st.Name, err)
			}
		} else {
			st.Protection = c.Protection
		}
		if st.OwnRules {
			if err := validateRules(st.Rules); err != nil {
				return fmt.Errorf("site %q: %w", st.Name, err)
			}
		} else {
			st.Rules = cloneRules(c.Rules)
		}
		if st.OwnPage {
			if err := validatePage(&st.Page); err != nil {
				return fmt.Errorf("site %q: %w", st.Name, err)
			}
		} else {
			st.Page = c.Page
		}
	}
	return nil
}

func cloneRules(rs []Rule) []Rule {
	b, _ := json.Marshal(rs)
	var out []Rule
	_ = json.Unmarshal(b, &out)
	if out == nil {
		out = []Rule{}
	}
	return out
}

func validateRules(rules []Rule) error {
	if _, err := CompileRules(rules); err != nil {
		return err
	}
	ids := map[string]bool{}
	for i := range rules {
		r := &rules[i]
		r.ID = uniqueID(SlugID(r.Name, "rule"), ids)
		r.Difficulty = clamp(r.Difficulty, 0, 8)
	}
	return nil
}

// SlugID turns a name into a short readable ID ("My Blog" -> "my-blog").
// Letters of any script are kept; fallback is used for names without any.
func SlugID(name, fallback string) string {
	var b strings.Builder
	dash := false
	n := 0
	for _, c := range strings.ToLower(name) {
		if unicode.IsLetter(c) || unicode.IsDigit(c) {
			b.WriteRune(c)
			dash = false
			n++
		} else if !dash && b.Len() > 0 {
			b.WriteByte('-')
			dash = true
		}
		if n >= 48 {
			break
		}
	}
	s := strings.TrimSuffix(b.String(), "-")
	if s == "" {
		s = fallback
	}
	return s
}

// uniqueID returns base, or base-2, base-3... if taken, and marks it taken.
func uniqueID(base string, taken map[string]bool) string {
	id := base
	for j := 2; taken[id]; j++ {
		id = fmt.Sprintf("%s-%d", base, j)
	}
	taken[id] = true
	return id
}

func validateProtection(p *Protection) error {
	p.Difficulty = clamp(p.Difficulty, 1, 8)
	if !oneOf(p.DefaultAction, ActionAllow, ActionChallenge, ActionBlock) {
		p.DefaultAction = ActionChallenge
	}
	p.PassHours = clamp(p.PassHours, 1, 24*365)
	p.ChallengeMinutes = clamp(p.ChallengeMinutes, 1, 120)
	if p.CookieName == "" {
		p.CookieName = "tamamo-pass"
	}
	if !cookieName.MatchString(p.CookieName) {
		return errors.New("cookie name may only contain letters, digits, - and _")
	}
	p.CookieDomain = strings.TrimSpace(p.CookieDomain)
	p.MaxFailures = clamp(p.MaxFailures, 0, 10000)
	return nil
}

func validatePage(pg *Page) error {
	if err := validateTranslations(pg); err != nil {
		return err
	}
	if err := validatePalette("light", &pg.Light); err != nil {
		return err
	}
	if err := validatePalette("dark", &pg.Dark); err != nil {
		return err
	}
	if !oneOf(pg.ThemeMode, "light", "dark", "auto") {
		pg.ThemeMode = "auto"
	}
	if pg.Lang == "" || !langTag.MatchString(pg.Lang) {
		pg.Lang = "en"
	}
	if err := validateLanguage(pg); err != nil {
		return err
	}
	if !oneOf(pg.Font, "system", "serif", "rounded", "mono", "custom") {
		pg.Font = "system"
	}
	if !fontFamily.MatchString(pg.CustomFont) {
		return errors.New("custom font may only list font names, quotes, commas and dashes")
	}
	pg.FontScale = clamp(pg.FontScale, 70, 150)
	pg.HeadingWeight = clamp(pg.HeadingWeight/100*100, 300, 900)
	if !oneOf(pg.Align, "left", "center") {
		pg.Align = "center"
	}
	if !oneOf(pg.Layout, "card", "split", "minimal") {
		pg.Layout = "card"
	}
	pg.CardWidth = clamp(pg.CardWidth, 320, 1100)
	pg.Radius = clamp(pg.Radius, 0, 48)
	if !oneOf(pg.MascotPosition, "top", "left", "right", "bottom") {
		pg.MascotPosition = "top"
	}
	pg.MascotSize = clamp(pg.MascotSize, 48, 480)
	if !oneOf(pg.MascotAnimation, "none", "float", "bounce", "wiggle") {
		pg.MascotAnimation = "float"
	}
	if !oneOf(pg.Background, "solid", "dots", "grid", "stripes", "image") {
		pg.Background = "solid"
	}
	pg.BackgroundBlur = clamp(pg.BackgroundBlur, 0, 40)
	pg.BackgroundDim = clamp(pg.BackgroundDim, 0, 90)
	if !oneOf(pg.Progress, "bar", "ring", "dots", "spinner", "none") {
		pg.Progress = "bar"
	}
	pg.MinDisplayMs = clamp(pg.MinDisplayMs, 0, 15000)
	pg.SuccessDelayMs = clamp(pg.SuccessDelayMs, 0, 15000)
	if !oneOf(pg.CreditAlign, "left", "center", "right") {
		pg.CreditAlign = "center"
	}
	if err := CheckCustomCSS(pg.CustomCSS); err != nil {
		return err
	}
	if utf8.RuneCountInString(pg.Title) > 200 {
		return errors.New("page title is too long")
	}
	return nil
}

// CheckCustomCSS rejects CSS that could break out of the <style> element or
// target the credit line, which must stay visible.
func CheckCustomCSS(css string) error {
	l := strings.ToLower(css)
	if strings.Contains(l, "<") {
		return errors.New("custom CSS cannot contain '<'")
	}
	if strings.Contains(l, "tm-credit") {
		return errors.New("custom CSS cannot target the Tamamo credit line")
	}
	if len(css) > 64*1024 {
		return errors.New("custom CSS is larger than 64 KB")
	}
	return nil
}

// ParsePrefix accepts "10.0.0.0/8" or a single address.
func ParsePrefix(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return p, err
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}

func NewID() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func newSecret() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// ---- Manager ----------------------------------------------------------------

type snapshot struct {
	cfg   *Config
	def   *SiteView
	sites []*SiteView
	byID  map[string]*SiteView
}

// SiteView is the resolved, ready-to-use settings of one site.
type SiteView struct {
	ID         string // DefaultSiteID for the default site
	Name       string
	Hosts      []string
	Target     string // resolved: the site's target or server.target
	Protection *Protection
	Rules      *RuleSet
	Page       *Page
	hosts      []matcher
}

func buildViews(c *Config) (*SiteView, []*SiteView, map[string]*SiteView, error) {
	rs, err := CompileRules(c.Rules)
	if err != nil {
		return nil, nil, nil, err
	}
	def := &SiteView{ID: DefaultSiteID, Name: "Default site", Target: c.Server.Target,
		Protection: &c.Protection, Rules: rs, Page: &c.Page}
	byID := map[string]*SiteView{DefaultSiteID: def}
	var views []*SiteView
	for i := range c.Sites {
		st := &c.Sites[i]
		v := &SiteView{ID: st.ID, Name: st.Name, Hosts: st.Hosts, Target: st.Target,
			Protection: &c.Protection, Rules: rs, Page: &c.Page}
		if v.Target == "" {
			v.Target = c.Server.Target
		}
		if st.OwnProtection {
			v.Protection = &st.Protection
		}
		if st.OwnRules {
			if v.Rules, err = CompileRules(st.Rules); err != nil {
				return nil, nil, nil, err
			}
		}
		if st.OwnPage {
			v.Page = &st.Page
		}
		for _, h := range st.Hosts {
			m, err := compilePattern(h, true, true)
			if err != nil {
				return nil, nil, nil, err
			}
			v.hosts = append(v.hosts, m)
		}
		views = append(views, v)
		byID[v.ID] = v
	}
	return def, views, byID, nil
}

// ForHost returns the site whose host patterns match host (port ignored).
// Exact host names win over wildcards; otherwise sites are tried in order.
// Hosts no site claims get the default site.
func (m *Manager) ForHost(host string) *SiteView {
	s := m.eff.Load()
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, v := range s.sites {
		for _, h := range v.Hosts {
			if h == host {
				return v
			}
		}
	}
	for _, v := range s.sites {
		for _, hm := range v.hosts {
			if hm(host) {
				return v
			}
		}
	}
	return s.def
}

// Site returns a site by ID (DefaultSiteID for the default site), or nil.
func (m *Manager) Site(id string) *SiteView { return m.eff.Load().byID[id] }

// Sites returns the default site followed by every configured site.
func (m *Manager) Sites() []*SiteView {
	s := m.eff.Load()
	return append([]*SiteView{s.def}, s.sites...)
}

// Env variables that always override the stored file.
var envOverrides = []struct{ env, key string }{
	{"TAMAMO_LISTEN", "server.listen"},
	{"TAMAMO_TARGET", "server.target"},
	{"TAMAMO_ENABLE_API", "admin.enabled"},
	{"TAMAMO_ADMIN_LISTEN", "admin.listen"},
	{"TAMAMO_IP_SOURCE", "server.ip_source"},
	// The admin login itself is written by cmd/tamamo (it needs hashing);
	// the lock only stops the web UI from changing it.
	{"TAMAMO_ADMIN_USERNAME", "admin.login"},
}

func (m *Manager) applyEnv(c *Config) {
	if v := os.Getenv("TAMAMO_LISTEN"); v != "" {
		c.Server.Listen = v
	}
	if v := os.Getenv("TAMAMO_TARGET"); v != "" {
		c.Server.Target = v
	}
	c.Admin.Enabled = APIEnabled()
	if v := os.Getenv("TAMAMO_ADMIN_LISTEN"); v != "" {
		c.Admin.Listen = v
	}
	if v := os.Getenv("TAMAMO_IP_SOURCE"); v != "" && oneOf(v, "remote", "x-forwarded-for", "x-real-ip", "cf-connecting-ip") {
		c.Server.IPSource = v
	}
}

func (m *Manager) publish() error {
	eff := m.stored.Clone()
	m.applyEnv(eff)
	if err := ValidateTarget(eff.Server.Target); err != nil {
		return fmt.Errorf("TAMAMO_TARGET: %w", err)
	}
	def, sites, byID, err := buildViews(eff)
	if err != nil {
		return err
	}
	m.eff.Store(&snapshot{cfg: eff, def: def, sites: sites, byID: byID})
	return nil
}

// Get returns the effective config. Treat it as read-only.
func (m *Manager) Get() *Config { return m.eff.Load().cfg }

// Rules returns the compiled global rule set (the default site's rules).
func (m *Manager) Rules() *RuleSet { return m.eff.Load().def.Rules }

// Stored returns a copy of the config as stored on disk (without env overrides).
func (m *Manager) Stored() *Config {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.stored.Clone()
}

// Locked lists setting keys fixed by environment variables, mapped to the variable name.
func (m *Manager) Locked() map[string]string { return m.locked }

// Update applies fn to a copy of the stored config, validates, saves and publishes it.
func (m *Manager) Update(fn func(c *Config) error) error {
	m.mu.Lock()
	next := m.stored.Clone()
	if err := fn(next); err != nil {
		m.mu.Unlock()
		return err
	}
	if next.Secret == "" {
		next.Secret = m.stored.Secret
	}
	if err := next.Validate(); err != nil {
		m.mu.Unlock()
		return err
	}
	prev := m.stored
	m.stored = next
	if err := m.publish(); err != nil {
		m.stored = prev
		m.mu.Unlock()
		return err
	}
	if err := m.save(); err != nil {
		m.mu.Unlock()
		return err
	}
	subs := append([]func(*Config){}, m.subs...)
	m.mu.Unlock()
	m.notifyRenames(siteRenames(prev, next))
	for _, s := range subs {
		s(m.Get())
	}
	return nil
}

// Subscribe registers a callback run after every successful update.
func (m *Manager) Subscribe(fn func(*Config)) {
	m.mu.Lock()
	m.subs = append(m.subs, fn)
	m.mu.Unlock()
}

// RotateSecret replaces the signing secret, signing every visitor out.
func (m *Manager) RotateSecret() error {
	return m.Update(func(c *Config) error {
		c.Secret = newSecret()
		return nil
	})
}

// APIEnabled reports whether TAMAMO_ENABLE_API turns the admin API on. The API
// (which the optional web UI container talks to) is off unless it is
// set to true, 1, yes or on.
func APIEnabled() bool {
	v := strings.TrimSpace(os.Getenv("TAMAMO_ENABLE_API"))
	return v == "1" || strings.EqualFold(v, "true") || strings.EqualFold(v, "yes") || strings.EqualFold(v, "on")
}
