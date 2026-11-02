package server

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/tamamo/tamamo/internal/config"
	"github.com/tamamo/tamamo/internal/modules"
	"github.com/tamamo/tamamo/internal/page"
)

// ModulesURL is where page modules' files are served:
// ModulesURL + "/<name>/<file>".
const ModulesURL = "/.tamamo/modules"

// checkModule is a ready-to-run go or webhook module.
type checkModule struct {
	cfg config.ModuleConfig
	c   modules.Checker
}

// SetDataDir sets the data directory (page modules live in <dir>/modules).
// By default it is the image store's data directory. Call it before serving.
func (s *Server) SetDataDir(dir string) { s.dataDir = dir }

// ModulesDir returns <data>/modules, or "" when no data directory is known.
func (s *Server) ModulesDir() string {
	if s.dataDir == "" {
		return ""
	}
	return filepath.Join(s.dataDir, "modules")
}

// buildModules creates the checkers of cfg's enabled check modules. Modules
// whose config didn't change keep their checker, so e.g. rate-limit counters
// survive unrelated config updates.
func (s *Server) buildModules(cfg *config.Config) []checkModule {
	s.modMu.Lock()
	defer s.modMu.Unlock()
	next := map[string]modules.Checker{}
	var out []checkModule
	for _, m := range cfg.Modules {
		if !m.Enabled || (m.Type != config.ModuleGo && m.Type != config.ModuleWebhook) {
			continue
		}
		kb, _ := json.Marshal(m)
		key := string(kb)
		c := s.modCache[key]
		if c == nil {
			var err error
			c, err = newChecker(&m)
			if err != nil {
				slog.Error("module could not be started; it is skipped", "module", m.Name, "err", err)
				continue
			}
		}
		next[key] = c
		out = append(out, checkModule{cfg: m, c: c})
	}
	s.modCache = next
	return out
}

func newChecker(m *config.ModuleConfig) (modules.Checker, error) {
	if m.Type == config.ModuleGo {
		return modules.New(m.GoModule(), m.Settings)
	}
	o, err := m.WebhookOptions()
	if err != nil {
		return nil, err
	}
	return modules.NewWebhook(o)
}

// runModules asks the site's check modules about a request, in order. The
// first module with an opinion decides; ok is false when none had one.
func (s *Server) runModules(r *http.Request, d *derived, req modules.Request) (dec modules.Decision, name string, ok bool) {
	for i := range d.mods {
		m := &d.mods[i]
		if !m.cfg.AppliesTo(req.Site) {
			continue
		}
		md, err := safeCheck(m.c, r, req)
		if err != nil {
			slog.Warn("module failed", "module", m.cfg.Name, "on_error", m.cfg.OnError, "err", err)
			if m.cfg.OnError == config.ActionBlock || m.cfg.OnError == config.ActionChallenge {
				return modules.Decision{Action: m.cfg.OnError, Reason: "module error"}, m.cfg.Name, true
			}
			continue
		}
		if !modules.ValidAction(md.Action) {
			slog.Warn("module returned an unknown action; ignored", "module", m.cfg.Name, "action", md.Action)
			continue
		}
		if md.Action != modules.NoOpinion {
			if md.Difficulty < 0 || md.Difficulty > 8 {
				md.Difficulty = 0
			}
			return md, m.cfg.Name, true
		}
	}
	return modules.Decision{}, "", false
}

// safeCheck runs a checker, turning a panic into an error.
func safeCheck(c modules.Checker, r *http.Request, req modules.Request) (d modules.Decision, err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("panic: %v", p)
		}
	}()
	return c.Check(r.Context(), req)
}

// pageModules returns the page modules to add to a page of site siteID.
func (s *Server) pageModules(cfg *config.Config, siteID string) []page.Module {
	return page.LoadModules(cfg.Modules, siteID, s.ModulesDir(), ModulesURL)
}

// serveModuleFile serves ModulesURL/<name>/<file> for a page module that is
// switched on for the request's site.
func (s *Server) serveModuleFile(w http.ResponseWriter, r *http.Request, rest string) {
	name, file, _ := strings.Cut(rest, "/")
	site := s.mgr.ForHost(r.Host)
	cfg := s.state().cfg
	for i := range cfg.Modules {
		m := &cfg.Modules[i]
		if m.Type == config.ModulePage && m.Name == name && m.AppliesTo(site.ID) {
			modules.ServeFile(w, r, s.ModulesDir(), name, file)
			return
		}
	}
	http.NotFound(w, r)
}
