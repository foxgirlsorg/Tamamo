package page

import (
	"html/template"

	"github.com/foxgirlsorg/tamamo/internal/modules"
	"github.com/foxgirlsorg/tamamo/module"
)

// ExtendWith collects what the modules switched on for req's site add to a
// page, in config order. assetBase is where their static files are served
// (e.g. "/.tamamo/modules"). Snippets are closed (see CloseFragment) so a
// module can't swallow the rest of the page, the credit line included.
func ExtendWith(list []*modules.Instance, req module.PageRequest, assetBase string) []Module {
	var out []Module
	for _, p := range modules.PageParts(list, req, assetBase) {
		out = append(out, Module{
			Name:    p.Name,
			Head:    template.HTML(CloseFragment(p.Head)), //nolint:gosec // compiled-in module code
			Body:    template.HTML(CloseFragment(p.Body)), //nolint:gosec // compiled-in module code
			Styles:  p.Styles,
			Scripts: p.Scripts,
		})
	}
	return out
}
