// Package web embeds Tamamo's static files: default mascots and the
// checking page (template, solver and worker scripts).
package web

import "embed"

//go:embed all:mascot all:challenge
var FS embed.FS
