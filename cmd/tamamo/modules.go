package main

// Compiled-in Go modules.
//
// The built-in modules ("ratelimit" and "bypass-header") live in
// internal/modules and are always available. To add your own:
//
//  1. Write a package that calls modules.Register in an init function
//     (see modules/example for a complete one, and the package comment of
//     internal/modules for the API).
//  2. Add a blank import of it below.
//  3. Rebuild (go build ./cmd/tamamo or docker build .).
//
// The module then appears in the web UI (GET /api/modules) and is switched
// on with a config entry like {"type": "go", "name": "<name>", "enabled": true}.
import (
	_ "github.com/tamamo/tamamo/internal/modules" // built-ins
	// _ "github.com/tamamo/tamamo/modules/example"
)
