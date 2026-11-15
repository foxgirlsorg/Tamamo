package admin

import (
	"net/http"

	"github.com/foxgirlsorg/tamamo/internal/modules"
	chpage "github.com/foxgirlsorg/tamamo/internal/page"
	"github.com/foxgirlsorg/tamamo/module"
)

// URLs under which the admin API serves modules' files. The web UI
// container proxies everything below /assets/modules/ to the backend.
const (
	moduleKitURL    = "/assets/modules/kit"    // the UI kit (tamamo.css, tamamo.js)
	moduleUIURL     = "/assets/modules/ui"     // + /<module id>/<file>: web UI pages
	moduleStaticURL = "/assets/modules/static" // + /<module id>/<file>: files for the preview
)

// moduleUIPolicy is sent with modules' web UI pages. They are shown in a
// frame inside the web UI, on its origin: they may load their own files and
// the kit and call the admin API, nothing else. Inline scripts are refused.
const moduleUIPolicy = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; " +
	"img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self'; frame-src 'none'; " +
	"frame-ancestors 'self'; base-uri 'self'; form-action 'self'; object-src 'none'"

// availableModule describes one module compiled into this build.
type availableModule struct {
	module.Info
	HasUI     bool `json:"has_ui"`
	HasStatic bool `json:"has_static"`
}

// runningModule describes one enabled entry of the modules section.
type runningModule struct {
	Name   string   `json:"name"`
	Module string   `json:"module"` // the registered ID it runs
	Hooks  []string `json:"hooks"`
	// Error is why the module's background work could not start, or "".
	Error string `json:"error"`
}

// listModules answers GET /api/modules: the modules compiled into this build
// (with their settings and pages) and the ones running right now.
func (h *handler) listModules(w http.ResponseWriter, r *http.Request, _ ctxSession) {
	available := []availableModule{}
	for _, info := range module.Registered() {
		if info.Settings == nil {
			info.Settings = []module.Field{}
		}
		if info.Pages == nil {
			info.Pages = []module.Page{}
		}
		available = append(available, availableModule{Info: info, HasUI: info.UI != nil, HasStatic: info.Static != nil})
	}
	running := []runningModule{}
	if h.o.Modules != nil {
		for _, in := range h.o.Modules.Instances() {
			running = append(running, runningModule{
				Name: in.Cfg.Name, Module: in.Info.ID, Hooks: in.Hooks(), Error: in.StartError(),
			})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"available": available,
		"running":   running,
		"kit_url":   moduleKitURL,
		"ui_url":    moduleUIURL,
	})
}

// moduleAPI hands /api/x/<name>/<rest> to the running module's AdminHandler,
// with the path cut down to "/<rest>". The caller is signed in, and the
// CSRF header was checked for anything but GET and HEAD.
func (h *handler) moduleAPI(w http.ResponseWriter, r *http.Request, _ ctxSession) {
	name := r.PathValue("name")
	var in *modules.Instance
	if h.o.Modules != nil {
		in = h.o.Modules.Instance(name)
	}
	if in == nil {
		writeError(w, http.StatusNotFound, "no module called "+name+" is running")
		return
	}
	if in.Admin == nil {
		writeError(w, http.StatusNotFound, "module "+name+" has no admin API")
		return
	}
	modules.ServeStripped(w, r, "/"+r.PathValue("rest"), name, in.Admin.ServeAdmin)
}

// moduleKit serves the UI kit for modules' pages.
func (h *handler) moduleKit(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-cache")
	modules.ServeFS(w, r, modules.Kit, r.PathValue("file"), false)
}

// moduleUI serves a file of a module's web UI pages (Info.UI) to a
// signed-in admin.
func (h *handler) moduleUI(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.currentSession(r); !ok {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	info, ok := module.Lookup(r.PathValue("id"))
	if !ok || info.UI == nil {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	hd := w.Header()
	hd.Set("Content-Security-Policy", moduleUIPolicy)
	hd.Set("X-Frame-Options", "SAMEORIGIN")
	// A rebuilt module must show its new pages at once.
	hd.Set("Cache-Control", "no-cache")
	modules.ServeFS(w, r, info.UI, r.PathValue("file"), true)
}

// moduleStatic serves a module's static files (Info.Static) so the
// checking-page preview can load them. Admin-only, enabled or not: the
// preview may show unsaved settings.
func (h *handler) moduleStatic(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.currentSession(r); !ok {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	info, ok := module.Lookup(r.PathValue("id"))
	if !ok || info.Static == nil {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	modules.ServeFS(w, r, info.Static, r.PathValue("file"), false)
}

// previewModules returns what the running modules add to the previewed page.
func (h *handler) previewModules(site, host, state, lang string) []chpage.Module {
	if h.o.Modules == nil {
		return nil
	}
	return chpage.ExtendWith(h.o.Modules.Instances(),
		module.PageRequest{Site: site, Host: host, State: state, Lang: lang, Preview: true}, moduleStaticURL)
}
