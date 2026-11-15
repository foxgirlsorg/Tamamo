package modules

import (
	"embed"
	"io/fs"
)

//go:embed kit
var kitFiles embed.FS

// Kit holds the files Tamamo offers to modules' web UI pages: a stylesheet
// that matches the web UI (tamamo.css) and a small script for talking to the
// module's admin API and to the web UI around the page (tamamo.js).
var Kit = func() fs.FS {
	sub, err := fs.Sub(kitFiles, "kit")
	if err != nil {
		panic(err) // the directory is embedded at build time
	}
	return sub
}()
