package admin

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"

	"github.com/tamamo/tamamo/internal/assets"
	"github.com/tamamo/tamamo/internal/config"
	chpage "github.com/tamamo/tamamo/internal/page"
	"github.com/tamamo/tamamo/internal/server"
	"github.com/tamamo/tamamo/internal/stats"
)

// ---- state, setup, login ----------------------------------------------------

func (h *handler) setupRequired() bool {
	st := h.o.Config.Stored()
	return st.Admin.Username == "" || st.Admin.PasswordHash == ""
}

func (h *handler) state(w http.ResponseWriter, r *http.Request) {
	eff := h.o.Config.Get()
	s, authed := h.currentSession(r)
	restart := (h.o.RunningListen != "" && eff.Server.Listen != h.o.RunningListen) ||
		(h.o.RunningAdminListen != "" && eff.Admin.Listen != h.o.RunningAdminListen)
	out := map[string]any{
		"setup_required":   h.setupRequired(),
		"authenticated":    authed,
		"username":         "",
		"version":          h.o.Version,
		"restart_required": false,
		"admin_listen":     "",
		"listen":           "",
	}
	if authed {
		out["username"] = s.username
		out["restart_required"] = restart
		out["admin_listen"] = eff.Admin.Listen
		out["listen"] = eff.Server.Listen
	}
	writeJSON(w, http.StatusOK, out)
}

type credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (h *handler) setup(w http.ResponseWriter, r *http.Request) {
	var req credentials
	if !readJSON(w, r, &req) {
		return
	}
	h.setupMu.Lock()
	defer h.setupMu.Unlock()
	if !h.setupRequired() {
		writeError(w, http.StatusConflict, "the admin login has already been created; please sign in")
		return
	}
	if err := validateCredentials(req.Username, req.Password); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	hash, err := hashPassword(req.Password)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not hash the password")
		return
	}
	if err := h.o.Config.Update(func(c *config.Config) error {
		c.Admin.Username = req.Username
		c.Admin.PasswordHash = hash
		return nil
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "could not save the login: "+err.Error())
		return
	}
	ttl := h.sessionTTL()
	setSessionCookie(w, r, h.sessions.create(req.Username, ttl), ttl)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "username": req.Username})
}

func (h *handler) checkLogin(username, password string) bool {
	st := h.o.Config.Stored()
	userOK := subtle.ConstantTimeCompare([]byte(username), []byte(st.Admin.Username)) == 1 && st.Admin.Username != ""
	hash := st.Admin.PasswordHash
	if !userOK || hash == "" {
		hash = getDummyHash()
	}
	passOK := verifyPassword(hash, password)
	return userOK && passOK && st.Admin.PasswordHash != ""
}

func (h *handler) login(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if d := h.limiter.blocked(ip); d > 0 {
		secs := int(d.Seconds()) + 1
		w.Header().Set("Retry-After", fmt.Sprint(secs))
		writeError(w, http.StatusTooManyRequests, fmt.Sprintf("too many failed sign-in attempts; try again in %s", humanDuration(secs)))
		return
	}
	var req credentials
	if !readJSON(w, r, &req) {
		return
	}
	if h.setupRequired() {
		writeError(w, http.StatusConflict, "no admin login exists yet; create one first")
		return
	}
	if len(req.Password) > maxPassword || !h.checkLogin(req.Username, req.Password) {
		h.limiter.fail(ip)
		writeError(w, http.StatusUnauthorized, "wrong username or password")
		return
	}
	h.limiter.succeed(ip)
	ttl := h.sessionTTL()
	setSessionCookie(w, r, h.sessions.create(req.Username, ttl), ttl)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "username": req.Username})
}

func humanDuration(secs int) string {
	if secs < 60 {
		return fmt.Sprintf("%d seconds", secs)
	}
	m := (secs + 59) / 60
	if m == 1 {
		return "a minute"
	}
	return fmt.Sprintf("%d minutes", m)
}

func (h *handler) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		h.sessions.delete(c.Value)
	}
	clearSessionCookie(w, r)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ---- config -----------------------------------------------------------------

func (h *handler) configResponse() map[string]any {
	var uploads map[string]bool
	if h.o.Assets != nil {
		uploads = h.o.Assets.Custom()
	}
	return map[string]any{
		"config":    h.o.Config.Stored().Public(),
		"effective": h.o.Config.Get().Public(),
		"locked":    h.o.Config.Locked(),
		"uploads":   uploads,
		"defaults": map[string]any{
			"rules":   config.DefaultRules(),
			"page":    config.DefaultPage(),
			"presets": rulePresets(),
		},
	}
}

func (h *handler) getConfig(w http.ResponseWriter, r *http.Request, _ ctxSession) {
	writeJSON(w, http.StatusOK, h.configResponse())
}

func (h *handler) putConfig(w http.ResponseWriter, r *http.Request, _ ctxSession) {
	var in config.Config
	if !readJSON(w, r, &in) {
		return
	}
	merge := func(c *config.Config) {
		secret, user, hash, enabled := c.Secret, c.Admin.Username, c.Admin.PasswordHash, c.Admin.Enabled
		*c = *in.Clone()
		c.Secret, c.Admin.Username, c.Admin.PasswordHash = secret, user, hash
		// Whether the admin API runs is decided by TAMAMO_ENABLE_API, not the file.
		c.Admin.Enabled = enabled
	}
	// Validate first so bad input is a 400, not a server error.
	check := h.o.Config.Stored()
	merge(check)
	if err := check.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := h.o.Config.Update(func(c *config.Config) error { merge(c); return nil }); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, h.configResponse())
}

// ---- stats ------------------------------------------------------------------

func (h *handler) getStats(w http.ResponseWriter, r *http.Request, _ ctxSession) {
	if h.o.Stats == nil {
		writeJSON(w, http.StatusOK, stats.Snapshot{})
		return
	}
	writeJSON(w, http.StatusOK, h.o.Stats.Snapshot(r.URL.Query().Get("site")))
}

func (h *handler) resetStats(w http.ResponseWriter, r *http.Request, _ ctxSession) {
	if h.o.Stats != nil {
		h.o.Stats.Reset()
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ---- preview ----------------------------------------------------------------

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (h *handler) preview(w http.ResponseWriter, r *http.Request, _ ctxSession) {
	var req struct {
		Page  *config.Page `json:"page"`
		State string       `json:"state"`
		// Lang shows one of the page's translations ("" = main texts).
		Lang string `json:"lang"`
		// Site picks whose page modules are shown ("" = the default site).
		Site string `json:"site"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	switch req.State {
	case "":
		req.State = "checking"
	case "checking", "success", "denied", "error":
	default:
		writeError(w, http.StatusBadRequest, "state must be checking, success, denied or error")
		return
	}
	cfg := h.o.Config.Get().Clone()
	if req.Page != nil {
		cfg.Page = *req.Page
	}
	if err := cfg.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	lang := strings.ToLower(strings.TrimSpace(req.Lang))
	if lang == strings.ToLower(cfg.Page.Lang) {
		lang = ""
	}
	if _, ok := cfg.Page.Translations[lang]; lang != "" && !ok {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("the page has no %q translation", req.Lang))
		return
	}
	site := req.Site
	if site == "" {
		site = config.DefaultSiteID
	}
	host := r.Host
	if hst, _, err := net.SplitHostPort(host); err == nil {
		host = hst
	}
	if host == "" || strings.ContainsAny(host, "<>\"'") {
		host = "example.com"
	}
	var images map[string]string
	if h.o.Assets != nil {
		images = h.o.Assets.URLs("/assets/img")
	}
	data := chpage.Data{
		State:      req.State,
		Host:       host,
		Preview:    true,
		Token:      randomHex(16),
		Random:     randomHex(16),
		Difficulty: cfg.Protection.Difficulty,
		Redirect:   "/",
		VerifyURL:  "",
		StaticURL:  "/assets/challenge",
		Images:     images,
		Lang:       lang,
		Modules:    chpage.LoadModules(cfg.Modules, site, h.modulesDir(), previewModulesURL),
	}
	if req.State == "error" {
		data.Message = ""
	}
	var buf bytes.Buffer
	if err := chpage.Render(&buf, &cfg.Page, data); err != nil {
		writeError(w, http.StatusInternalServerError, "could not render the page: "+err.Error())
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", previewContentSecurityPolicy)
	_, _ = w.Write(buf.Bytes())
}

// ---- uploads ----------------------------------------------------------------

func (h *handler) upload(w http.ResponseWriter, r *http.Request, _ ctxSession) {
	slot := r.PathValue("slot")
	if !assets.ValidSlot(slot) || h.o.Assets == nil {
		writeError(w, http.StatusNotFound, "unknown image slot")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, assets.MaxUpload+64<<10)
	f, _, err := r.FormFile("file")
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			writeError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("images can be at most %d MB", assets.MaxUpload>>20))
		} else {
			writeError(w, http.StatusBadRequest, "send the image as the multipart field \"file\"")
		}
		return
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, assets.MaxUpload+1))
	if err != nil {
		writeError(w, http.StatusBadRequest, "could not read the upload")
		return
	}
	if err := h.o.Assets.Save(slot, data); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"uploads": h.o.Assets.Custom()})
}

func (h *handler) deleteUpload(w http.ResponseWriter, r *http.Request, _ ctxSession) {
	slot := r.PathValue("slot")
	if !assets.ValidSlot(slot) || h.o.Assets == nil {
		writeError(w, http.StatusNotFound, "unknown image slot")
		return
	}
	if err := h.o.Assets.Delete(slot); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"uploads": h.o.Assets.Custom()})
}

// ---- account ----------------------------------------------------------------

func (h *handler) password(w http.ResponseWriter, r *http.Request, s ctxSession) {
	ip := clientIP(r)
	if d := h.limiter.blocked(ip); d > 0 {
		writeError(w, http.StatusTooManyRequests, fmt.Sprintf("too many failed attempts; try again in %s", humanDuration(int(d.Seconds())+1)))
		return
	}
	if env, ok := h.o.Config.Locked()["admin.login"]; ok {
		writeError(w, http.StatusConflict, "the admin login is set by "+env+" and TAMAMO_ADMIN_PASSWORD; change it there")
		return
	}
	var req struct {
		Current     string `json:"current"`
		NewUsername string `json:"new_username"`
		NewPassword string `json:"new_password"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	st := h.o.Config.Stored()
	if len(req.Current) > maxPassword || !verifyPassword(st.Admin.PasswordHash, req.Current) {
		h.limiter.fail(ip)
		writeError(w, http.StatusForbidden, "the current password is wrong")
		return
	}
	user := st.Admin.Username
	if req.NewUsername != "" {
		user = req.NewUsername
	}
	if req.NewUsername == "" && req.NewPassword == "" {
		writeError(w, http.StatusBadRequest, "enter a new username or a new password")
		return
	}
	pw := req.NewPassword
	if pw == "" {
		pw = req.Current
	}
	if err := validateCredentials(user, pw); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	hash := st.Admin.PasswordHash
	if req.NewPassword != "" {
		var err error
		if hash, err = hashPassword(req.NewPassword); err != nil {
			writeError(w, http.StatusInternalServerError, "could not hash the password")
			return
		}
	}
	if err := h.o.Config.Update(func(c *config.Config) error {
		c.Admin.Username = user
		c.Admin.PasswordHash = hash
		return nil
	}); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.limiter.succeed(ip)
	// Sign out every other session.
	h.sessions.keepOnly(s.token, user)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "username": user})
}

func (h *handler) rotateSecret(w http.ResponseWriter, r *http.Request, _ ctxSession) {
	if err := h.o.Config.RotateSecret(); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ---- rule tester ------------------------------------------------------------

type testRequest struct {
	Method    string            `json:"method"`
	Host      string            `json:"host"`
	Path      string            `json:"path"`
	UserAgent string            `json:"user_agent"`
	IP        string            `json:"ip"`
	Headers   map[string]string `json:"headers"`
}

type testRule struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Action     string `json:"action"`
	Difficulty int    `json:"difficulty"`
}

func (h *handler) testRule(w http.ResponseWriter, r *http.Request, _ ctxSession) {
	var req testRequest
	if !readJSON(w, r, &req) {
		return
	}
	if req.Method == "" {
		req.Method = http.MethodGet
	}
	if req.Path == "" {
		req.Path = "/"
	}
	rr := config.RuleRequest{
		Method:    strings.ToUpper(strings.TrimSpace(req.Method)),
		Host:      strings.TrimSpace(req.Host),
		Path:      server.CanonicalPath(req.Path),
		UserAgent: req.UserAgent,
		Header:    http.Header{},
	}
	if s := strings.TrimSpace(req.IP); s != "" {
		ip, err := netip.ParseAddr(s)
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("%q is not an IP address", s))
			return
		}
		rr.IP = ip
	}
	for k, v := range req.Headers {
		if strings.TrimSpace(k) != "" {
			rr.Header.Add(strings.TrimSpace(k), v)
		}
	}
	if req.UserAgent != "" && rr.Header.Get("User-Agent") == "" {
		rr.Header.Set("User-Agent", req.UserAgent)
	}
	site := h.o.Config.ForHost(rr.Host)
	rule := site.Rules.Match(rr)
	prot := site.Protection

	out := map[string]any{"rule": nil, "site": map[string]string{"id": site.ID, "name": site.Name}}
	action := prot.DefaultAction
	reason := fmt.Sprintf("No rule of %s matched, so its default action applies.", site.Name)
	difficulty := prot.Difficulty
	if rule != nil {
		out["rule"] = testRule{ID: rule.ID, Name: rule.Name, Action: rule.Action, Difficulty: rule.Difficulty}
		action = rule.Action
		reason = fmt.Sprintf("Rule %q is the first enabled rule of %s that matches.", rule.Name, site.Name)
		if rule.Difficulty > 0 {
			difficulty = rule.Difficulty
		}
	}
	if !prot.Enabled {
		action = config.ActionAllow
		reason = fmt.Sprintf("Protection is switched off for %s, so every request goes straight through.", site.Name)
	}
	if action != config.ActionChallenge {
		difficulty = 0
	}
	out["action"] = action
	out["difficulty"] = difficulty
	out["reason"] = reason
	writeJSON(w, http.StatusOK, out)
}

// ---- rule presets -----------------------------------------------------------

type rulePreset struct {
	Key         string      `json:"key"`
	Label       string      `json:"label"`
	Description string      `json:"description"`
	Position    string      `json:"position"` // top | bottom
	Open        bool        `json:"open,omitempty"`
	Rule        config.Rule `json:"rule"`
}

func presetRule(name, action, note string, m config.Match) config.Rule {
	return config.Rule{Name: name, Enabled: true, Action: action, Note: note, Match: m}
}

// rulePresets are ready-made rules offered by the "Add preset" menu. The
// default rules come first, so a deleted one can be added back.
func rulePresets() []rulePreset {
	var out []rulePreset
	desc := map[string]string{
		"allow-robots-txt":                 "robots.txt, /.well-known/ and the favicon stay reachable.",
		"allow-ai-crawlers":                "ChatGPT, Claude, Perplexity and others fetching pages for their users.",
		"allow-google-tools":               "Search Console, Lighthouse, PageSpeed Insights.",
		"allow-archive-and-other-crawlers": "The Internet Archive and other archiving crawlers.",
		"allow-search-engines":             "Google, Bing, DuckDuckGo, Apple, Yandex, Baidu…",
		"allow-social-bots":                "Facebook, LinkedIn, Slack, X, Pinterest link previews.",
		"allow-telegram":                   "Telegram's link preview bot.",
		"deny-all-others":                  "Every other request has to pass the check once.",
	}
	for _, r := range config.DefaultRules() {
		pos := "top"
		if r.ID == "deny-all-others" {
			pos = "bottom"
		}
		key := r.ID
		r.ID = ""
		out = append(out, rulePreset{Key: key, Label: r.Name, Description: desc[key], Position: pos, Rule: r})
	}
	out = append(out,
		rulePreset{Key: "block-ai-scrapers", Label: "Block AI scrapers", Description: "Refuse known AI and LLM training crawlers.", Position: "top",
			Rule: presetRule("Block AI scrapers", config.ActionBlock, "Known AI and LLM training crawlers are refused outright.",
				config.Match{UserAgents: append([]string{}, config.AIScraperAgents...)})},
		rulePreset{Key: "allow-static", Label: "Allow static files", Description: "Stylesheets, scripts, images and fonts load without a check.", Position: "top",
			Rule: presetRule("Allow static files", config.ActionAllow, "Static assets are cheap to serve and pages need them to render.",
				config.Match{Paths: []string{"*.css", "*.js", "*.mjs", "*.map", "*.png", "*.jpg", "*.jpeg", "*.gif", "*.webp", "*.avif", "*.svg", "*.ico", "*.woff", "*.woff2", "*.ttf", "*.otf"}})},
		rulePreset{Key: "allow-cli", Label: "Let non-browser clients through", Description: "curl, wget, API libraries and feed readers.", Position: "top",
			Rule: presetRule("Let non-browser clients through", config.ActionAllow, "These clients can't solve the check. User agents are easy to fake, so only add this if you need it.",
				config.Match{UserAgents: []string{"curl/", "Wget/", "python-requests/", "python-httpx/", "Go-http-client/", "okhttp/", "HTTPie/", "PostmanRuntime/", "axios/", "node-fetch"}})},
		rulePreset{Key: "check-browsers", Label: "Check every browser", Description: "Anything that looks like a browser proves itself once.", Position: "bottom",
			Rule: presetRule("Check every browser", config.ActionChallenge, "Anything that claims to be a browser has to prove it once.",
				config.Match{UserAgents: []string{"*Mozilla*", "*Opera*"}})},
		rulePreset{Key: "block-ip", Label: "Block an IP range", Description: "Refuse a network you name (starts switched off).", Position: "top", Open: true,
			Rule: config.Rule{Name: "Block an IP range", Enabled: false, Action: config.ActionBlock, Note: "Add the addresses or CIDR ranges below, then switch the rule on."}},
	)
	return out
}
