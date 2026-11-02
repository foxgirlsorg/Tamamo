package page

import (
	"errors"
	"html/template"
	"io/fs"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/tamamo/tamamo/internal/config"
	"github.com/tamamo/tamamo/internal/modules"
)

// LoadModules collects the enabled page modules for site siteID, in config
// order, from modulesDir (<data>/modules). baseURL is where their files are
// served (e.g. "/.tamamo/modules"). Folders that are missing or unreadable
// are skipped with a log message.
func LoadModules(mods []config.ModuleConfig, siteID, modulesDir, baseURL string) []Module {
	var out []Module
	base := strings.TrimRight(baseURL, "/")
	for i := range mods {
		m := &mods[i]
		if m.Type != config.ModulePage || !m.AppliesTo(siteID) {
			continue
		}
		pf, err := modules.LoadPage(modulesDir, m.Name)
		if err != nil {
			if throttle(m.Name) {
				if errors.Is(err, fs.ErrNotExist) {
					slog.Warn("page module folder not found", "module", m.Name, "dir", modulesDir)
				} else {
					slog.Warn("page module could not be loaded", "module", m.Name, "err", err)
				}
			}
			continue
		}
		head, body := pf.Snippets(base)
		pm := Module{Name: m.Name, Head: template.HTML(head), Body: template.HTML(body)}
		u := base + "/" + m.Name + "/"
		if pf.Style {
			pm.Styles = append(pm.Styles, u+modules.StyleFile+"?v="+pf.Version)
		}
		if pf.Script {
			pm.Scripts = append(pm.Scripts, u+modules.ScriptFile+"?v="+pf.Version)
		}
		out = append(out, pm)
	}
	return out
}

var (
	warnMu   sync.Mutex
	warnedAt = map[string]time.Time{}
)

// throttle reports whether a warning about module name may be logged now
// (at most once a minute per module, so a broken module can't flood logs).
func throttle(name string) bool {
	warnMu.Lock()
	defer warnMu.Unlock()
	now := time.Now()
	if t, ok := warnedAt[name]; ok && now.Sub(t) < time.Minute {
		return false
	}
	if len(warnedAt) > 1000 {
		clear(warnedAt)
	}
	warnedAt[name] = now
	return true
}
