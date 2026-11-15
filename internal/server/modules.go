package server

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/foxgirlsorg/tamamo/internal/checks"
	"github.com/foxgirlsorg/tamamo/internal/config"
	"github.com/foxgirlsorg/tamamo/internal/modules"
	"github.com/foxgirlsorg/tamamo/internal/page"
	"github.com/foxgirlsorg/tamamo/internal/stats"
	"github.com/foxgirlsorg/tamamo/module"
)

const (
	// ModulesURL is where modules' static files are served:
	// ModulesURL + "/<module id>/<file>".
	ModulesURL = "/.tamamo/modules"
	// ModuleRoutesURL is where modules' own handlers live:
	// ModuleRoutesURL + "/<name>/<rest>".
	ModuleRoutesURL = "/.tamamo/x"
)

// siteChecks are the ready-to-run built-in checks of one protection section.
type siteChecks struct {
	bypass []*checks.Bypass
	rl     *checks.RateLimit
	// botsAction is what a fake search-engine crawler gets, or "" when the
	// verified bots check is off.
	botsAction string
	rlAction   string
	rlReason   string
	hooks      []siteHook
}

type siteHook struct {
	cfg config.Webhook
	wh  *checks.Webhook
}

// Modules returns the host that runs this server's modules.
func (s *Server) Modules() *modules.Host { return s.host }

// Close stops the modules' background work.
func (s *Server) Close() { s.host.Close() }

// buildChecks creates the built-in checks of the global protection section
// and of every site with its own. Checks whose settings didn't change are
// kept, so rate-limit counters and webhook caches survive unrelated config
// updates.
func (s *Server) buildChecks(cfg *config.Config) map[*config.Protection]*siteChecks {
	s.checkMu.Lock()
	defer s.checkMu.Unlock()
	next := map[string]any{}
	out := map[*config.Protection]*siteChecks{}
	build := func(scope string, p *config.Protection) {
		sc := &siteChecks{}
		for _, b := range p.BypassHeaders {
			bp, err := checks.NewBypass(b.Name, b.Header, b.Value)
			if err != nil {
				slog.Error("bypass header skipped", "name", b.Name, "err", err)
				continue
			}
			sc.bypass = append(sc.bypass, bp)
		}
		if p.VerifiedBots.Enabled {
			sc.botsAction = p.VerifiedBots.Action
		}
		if rl := p.RateLimit; rl.Enabled {
			kb, _ := json.Marshal(rl)
			key := "rl\x00" + scope + "\x00" + string(kb)
			lim, _ := s.checkCache[key].(*checks.RateLimit)
			if lim == nil {
				lim = checks.NewRateLimit(rl.Requests, time.Duration(rl.WindowSeconds)*time.Second, rl.IPv6Prefix, rl.MaxIPs)
				lim.SetClock(func() time.Time { return s.now() })
			}
			next[key] = lim
			sc.rl, sc.rlAction = lim, rl.Action
			sc.rlReason = fmt.Sprintf("more than %d requests in %ds", rl.Requests, rl.WindowSeconds)
		}
		for _, w := range p.Webhooks {
			if !w.Enabled {
				continue
			}
			kb, _ := json.Marshal(w)
			key := "wh\x00" + scope + "\x00" + string(kb)
			wh, _ := s.checkCache[key].(*checks.Webhook)
			if wh == nil {
				var err error
				if wh, err = checks.NewWebhook(w.WebhookOptions()); err != nil {
					slog.Error("webhook skipped", "name", w.Name, "err", err)
					continue
				}
			}
			next[key] = wh
			sc.hooks = append(sc.hooks, siteHook{cfg: w, wh: wh})
		}
		out[p] = sc
	}
	build("global", &cfg.Protection)
	for i := range cfg.Sites {
		if st := &cfg.Sites[i]; st.OwnProtection {
			build("site:"+st.ID, &st.Protection)
		}
	}
	s.checkCache = next
	return out
}

// runChecks asks everything that runs before the rules about a request:
// bypass headers, the rate limit, webhooks and then the modules, in config
// order. The first one with an opinion decides; ok is false when none had
// one. label names what decided, for the statistics.
func (s *Server) runChecks(r *http.Request, d *derived, site *config.SiteView, req *module.Request) (dec module.Decision, label string, ok bool) {
	if sc := d.core[site.Protection]; sc != nil {
		for _, b := range sc.bypass {
			if b.Match(req.Header) {
				return module.Decision{Action: module.Allow, Reason: "bypass header"}, "bypass:" + b.Name, true
			}
		}
		if sc.botsAction != "" {
			if name, claimed := checks.ClaimedBot(req.UserAgent); claimed {
				ok, err := s.bots.Verify(r.Context(), name, req.IP)
				if err != nil {
					slog.Warn("verified bots: lookup failed", "bot", name, "ip", req.IP, "err", err)
					return module.Decision{Action: module.Challenge, Reason: "could not verify " + name}, "verified-bots", true
				}
				if !ok {
					return module.Decision{Action: sc.botsAction, Reason: "not really " + name}, "verified-bots", true
				}
			}
		}
		if sc.rl != nil && sc.rl.Over(req.IP) {
			return module.Decision{Action: sc.rlAction, Reason: sc.rlReason}, "ratelimit", true
		}
		for i := range sc.hooks {
			h := &sc.hooks[i]
			md, err := h.wh.Check(r.Context(), req)
			if dec, ok := settle(md, err, h.cfg.OnError, "webhook", h.cfg.Name); ok {
				return dec, "webhook:" + h.cfg.Name, true
			}
		}
	}
	for _, in := range d.mods {
		if in.Checker == nil || !in.Cfg.AppliesTo(req.Site) {
			continue
		}
		md, err := modules.Check(r.Context(), in, req)
		if dec, ok := settle(md, err, in.Cfg.OnError, "module", in.Cfg.Name); ok {
			return dec, "module:" + in.Cfg.Name, true
		}
	}
	return module.Decision{}, "", false
}

// settle turns a check's answer into a decision: ok is false when the check
// had no opinion (or failed and on_error says to carry on).
func settle(md module.Decision, err error, onError, kind, name string) (module.Decision, bool) {
	if err != nil {
		slog.Warn(kind+" failed", "name", name, "on_error", onError, "err", err)
		if onError == config.ActionBlock || onError == config.ActionChallenge {
			return module.Decision{Action: onError, Reason: kind + " error"}, true
		}
		return module.Decision{}, false
	}
	if !module.ValidAction(md.Action) {
		slog.Warn(kind+" returned an unknown action; ignored", "name", name, "action", md.Action)
		return module.Decision{}, false
	}
	if md.Action == module.NoOpinion {
		return module.Decision{}, false
	}
	if md.Difficulty < 0 || md.Difficulty > 8 {
		md.Difficulty = 0
	}
	return md, true
}

// observe tells the modules about a recorded event.
func (s *Server) observe(e stats.Event) {
	mods := s.state().mods
	if len(mods) == 0 {
		return
	}
	modules.Observe(mods, module.Event{
		Time: e.Time, Kind: e.Kind, Site: e.Site, Host: e.Host, Path: e.Path,
		UserAgent: e.UA, IP: e.IP, Rule: e.Rule,
	})
}

// pageModules returns what the modules add to a page of site siteID.
func (s *Server) pageModules(siteID, host, state, lang string) []page.Module {
	return page.ExtendWith(s.state().mods, module.PageRequest{Site: siteID, Host: host, State: state, Lang: lang}, ModulesURL)
}

// serveModuleFile serves ModulesURL/<module id>/<file> from the static files
// of a module that is switched on for the request's site.
func (s *Server) serveModuleFile(w http.ResponseWriter, r *http.Request, rest string) {
	id, file, _ := strings.Cut(rest, "/")
	site := s.mgr.ForHost(r.Host)
	for _, in := range s.state().mods {
		if in.Info.ID == id && in.Info.Static != nil && in.Cfg.AppliesTo(site.ID) {
			modules.ServeFS(w, r, in.Info.Static, file, false)
			return
		}
	}
	http.NotFound(w, r)
}

// serveModuleRoute hands ModuleRoutesURL/<name>/<rest> to the module's own
// handler, with the path cut down to "/<rest>".
func (s *Server) serveModuleRoute(w http.ResponseWriter, r *http.Request, rest string) {
	name, sub, _ := strings.Cut(rest, "/")
	site := s.mgr.ForHost(r.Host)
	var in *modules.Instance
	for _, m := range s.state().mods {
		if m.Cfg.Name == name && m.Public != nil && m.Cfg.AppliesTo(site.ID) {
			in = m
			break
		}
	}
	if in == nil {
		http.NotFound(w, r)
		return
	}
	modules.ServeStripped(w, r, "/"+sub, in.Cfg.Name, in.Public.ServeHTTP)
}
