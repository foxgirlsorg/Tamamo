<div align="center">

<img src="web/mascot/checking.png" width="140" alt="Eru, the foxgirls.org mascot" />

<h1>TAMAMO</h1>

**A proof-of-work gate that keeps scrapers and AI crawlers off your site.**

[![Docs](https://img.shields.io/badge/Docs-Tamamo--docs-de6161?style=flat-square)](https://tamamo.foxgirls.org/)
[![Image](https://img.shields.io/badge/Image-ghcr.io-de6161?style=flat-square&logo=docker&logoColor=white)](https://github.com/foxgirlsorg/Tamamo/pkgs/container/tamamo)
[![Telegram](https://img.shields.io/badge/Telegram-@foxgirlsorg-de6161?style=flat-square&logo=telegram&logoColor=white)](https://t.me/foxgirlsorg)
[![Website](https://img.shields.io/badge/Website-foxgirls.org-de6161?style=flat-square)](https://foxgirls.org)
[![License](https://img.shields.io/badge/License-MIT-de6161?style=flat-square)](LICENSE)

</div>

---

Tamamo sits in front of your website and asks every browser to prove it is a real browser before letting it in. People see a short "checking your browser" page once and then browse normally. Scrapers that hammer your site pay for every page.

This repo is the Go backend. It runs on its own. The admin web UI is an optional second container: [Tamamo-webui](https://github.com/foxgirlsorg/Tamamo-webui). Full documentation: [Tamamo-docs](https://tamamo.foxgirls.org/).

## Features

- **One static binary** and one container, with SQLite for statistics
- **SHA-256 proof of work** solved in the browser, usually in well under a second
- **Plain rules**: allow, check or block by path, user agent, IP, method, host or header
- **Multiple sites** from one instance, each with its own target, rules and checking page
- **Your own checking page**: texts, colours, layout, mascot, background and translations
- **Checks before the rules**: bypass headers, a rate limit and webhooks to your own service
- **Modules**: Go packages compiled into the binary, with their own settings and web UI pages
- **Two modes**: a reverse proxy, or an auth endpoint for nginx `auth_request`, Caddy `forward_auth` and Traefik ForwardAuth
- **No web UI needed**: one commented `tamamo.yaml`, environment variables and flags, reloaded on change

## How it works

1. A request arrives. The built-in checks run first, then the modules, then your rules from top to bottom. The first one that decides wins: **Allow**, **Check** or **Block**.
2. **Check** shows the checking page. The browser looks for a number that, hashed with a random challenge, starts with *N* zeros (*N* is the difficulty).
3. A correct answer earns a signed pass cookie, valid for one week by default. It can be tied to the visitor's network and browser, so a copied cookie does not work elsewhere.
4. **Block** shows the "access denied" page with HTTP 403.

## Quick start

Download a compose file from the docs ([Installation](https://tamamo.foxgirls.org/guide/installation)) into an empty folder, then:

```bash
mkdir data
sudo chown 65532:65532 data   # Linux only: the container runs as uid 65532
docker compose up -d
```

| URL | What |
| --- | --- |
| <http://localhost:8923> | Your site, protected |
| <http://localhost:8081> | Admin web UI (web UI compose file only) |

The first person to open the web UI creates the login, so open it right away, or set `TAMAMO_ADMIN_USERNAME` and `TAMAMO_ADMIN_PASSWORD` first. Point `TAMAMO_TARGET` at your application.

Without Compose, the backend runs alone with no web UI:

```bash
docker run -d -p 8923:8923 \
  -e TAMAMO_TARGET=http://host.docker.internal:3000 \
  -v "$(pwd)/data:/data" ghcr.io/foxgirlsorg/tamamo:latest
```

Or build the binary:

```bash
go build -o tamamo ./cmd/tamamo
TAMAMO_TARGET=http://localhost:3000 ./tamamo -data ./data
```

## Configuration

Everything lives in `data/tamamo.yaml`: sites, rules, protection, the checking page and server settings. The web UI writes the same file, so you can switch between them at any time. The admin API, and with it the web UI, only runs while `TAMAMO_ENABLE_API=true`.

See the docs for each section: [configuration](https://tamamo.foxgirls.org/config/), [environment variables](https://tamamo.foxgirls.org/reference/environment), [behind nginx, Caddy or Traefik](https://tamamo.foxgirls.org/guides/reverse-proxy) and [writing modules](https://tamamo.foxgirls.org/modules/).

## Development

```bash
# terminal 1: the backend, admin API on :8081
TAMAMO_ENABLE_API=true go run ./cmd/tamamo -data ./data

# terminal 2: the web UI, from the Tamamo-webui repo
npm run dev   # proxies /api and /assets to http://localhost:8081
```

Tests: `go test ./...`. A module example lives in `examples/hello`.

## Credits

- Made by [foxgirls.org](https://foxgirls.org).
- The mascot is **Eru**, the foxgirls.org mascot. Art by [Kiwi CR2](https://t.me/KiwiCR2).
- Inspired by [Anubis](https://github.com/TecharoHQ/anubis) by Techaro (MIT). Several tests are adapted from its test suite.

---

<div align="center">
  <sub>© 2026 <a href="https://foxgirls.org">foxgirls.org</a> &nbsp;·&nbsp; MIT License</sub>
</div>
