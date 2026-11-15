package admin

import (
	"net/http"

	"github.com/foxgirlsorg/tamamo/internal/config"
)

// rulesFileResponse is the rules part of tamamo.yaml, generated from
// the stored config, and where the settings file lives.
func (h *handler) rulesFileResponse(w http.ResponseWriter) {
	b, err := config.MarshalRulesYAML(h.o.Config.Stored())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not write the rules as YAML: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"yaml": string(b), "path": h.o.Config.ConfigPath()})
}

func (h *handler) getRulesFile(w http.ResponseWriter, r *http.Request, _ ctxSession) {
	h.rulesFileResponse(w)
}

func (h *handler) putRulesFile(w http.ResponseWriter, r *http.Request, _ ctxSession) {
	var req struct {
		YAML *string `json:"yaml"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if req.YAML == nil {
		writeError(w, http.StatusBadRequest, `send the rules as {"yaml": "..."}`)
		return
	}
	data := []byte(*req.YAML)
	// Check on a copy first so mistakes are a 400 with the line number.
	check := h.o.Config.Stored()
	if err := config.ApplyRulesYAML(check, data); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := check.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := h.o.Config.Update(func(c *config.Config) error {
		return config.ApplyRulesYAML(c, data)
	}); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.rulesFileResponse(w)
}
