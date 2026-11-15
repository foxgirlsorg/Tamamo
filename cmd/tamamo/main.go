// Command tamamo is a reverse proxy that asks browsers for a small SHA-256
// proof of work before letting them through, and blocks known scrapers.
//
// This is the standard build, without extra modules. To build one with
// modules, use tamamo-build (cmd/tamamo-build) or write your own main
// package: see the app package.
package main

import "github.com/foxgirlsorg/tamamo/app"

func main() { app.Main() }
