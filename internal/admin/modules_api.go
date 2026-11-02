package admin

import (
	"net/http"
	"path/filepath"
	"strings"

	"github.com/tamamo/tamamo/internal/modules"
)

// previewModulesURL is where the admin API serves page modules' files for the
// checking-page preview (see moduleFile).
const previewModulesURL = "/assets/modules"

// modulesDir returns the absolute <data>/modules directory, or "".
func (h *handler) modulesDir() string {
	if h.o.Assets == nil {
		return ""
	}
	dir := filepath.Join(h.o.Assets.DataDir(), "modules")
	if abs, err := filepath.Abs(dir); err == nil {
		dir = abs
	}
	return dir
}

// listModules answers GET /api/modules: the compiled-in Go modules, the page
// module folders found on disk and where those folders live.
func (h *handler) listModules(w http.ResponseWriter, r *http.Request, _ ctxSession) {
	dir := h.modulesDir()
	pages, err := modules.ListPages(dir)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list "+dir+": "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"available":    modules.Available(),
		"page_modules": pages,
		"data_dir":     dir,
		"modules_dir":  dir,
	})
}

// moduleFile serves GET /assets/modules/<name>/<file> so the preview can load
// page modules' stylesheets, scripts and images. Admin-only content of any
// folder under <data>/modules, enabled or not (the preview may show unsaved
// settings).
func (h *handler) moduleFile(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.currentSession(r); !ok {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, previewModulesURL+"/")
	name, file, _ := strings.Cut(rest, "/")
	modules.ServeFile(w, r, h.modulesDir(), name, file)
}
