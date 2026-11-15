# 🦊 Tamamo

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> **A proof-of-work gate that keeps scrapers and AI crawlers off your site.**

📚 **Documentation:** the full docs live in [Tamamo-docs](https://github.com/foxgirlsorg/Tamamo-docs). This README is the short version.

Tamamo sits in front of your website and asks every browser to prove it's a real browser before letting it in. Scrapers that hammer your site get blocked; people see a short "checking your browser" page once and then browse normally.

---

## ✨ Features

- 📦 **One binary** — Go standard library plus a YAML parser, nothing else
- 🧮 **SHA-256 proof of work** solved in the browser in well under a second
- 📜 **Rules in plain language** — allow, check or block by path, user agent, IP, method, host or header
- 🌐 **Multiple sites** from one instance, each with its own target, rules and checking page
- 🎨 **Fully customizable checking page** — texts, colors, layout, mascot, background, translations
- 🖥️ **Optional web UI** (its own container) with stats, every setting and a live page designer
- ✍️ **Works without the web UI** — one commented `tamamo.yaml`, env vars and CLI flags, hot-reloaded
- 🚦 **Built-in checks before the rules** — bypass headers, a rate limit and webhooks to your own service
- 🧩 **Modules** — real Go modules compiled into the binary, with their own settings form and pages in the web UI
- 🔀 **Reverse proxy mode or auth mode** — nginx `auth_request`, Caddy `forward_auth`, Traefik ForwardAuth
- 🐳 **Docker** out of the box

---

## 🏗️ Architecture

Two repositories, and an optional third container:

```
visitor ──▶ tamamo :8923 ──▶ your app          (this repo: the Go proxy)
                 ▲
                 │ /api/* (admin API, :8081 on the compose network)
                 │
admin ──▶ webui :8081 (nginx, serves the React app)   (tamamo_webui repo, optional)
```

- **Backend** (`tamamo`, this repo): the proxy, checking page, rules, stats and the admin JSON API. Runs alone.
- **Web UI** (`tamamo_webui`): a React single-page app built and served by its own nginx container. Same origin for the browser: nginx proxies `/api/` and the asset paths to the backend at `TAMAMO_API`. Remove the container and everything still works from `data/tamamo.yaml`.

## 🌀 How it works

1. A request arrives. The built-in checks run first (bypass headers, the rate limit, webhooks), then the modules, then your **rules** from top to bottom. The first one that decides wins: **Allow**, **Check** or **Block**. If nothing decides, the default action applies.
2. **Check** shows the checking page. The browser runs a SHA-256 proof of work: it has to find a number that, hashed together with a random challenge, starts with *N* zeros, where *N* is the difficulty. A real browser does this in about a second. A scraper fetching millions of pages pays that cost on every request.
3. When the answer is correct, Tamamo sets a signed **pass cookie**. The visitor stays verified for as long as you choose (one week by default).
4. **Block** shows the "access denied" page with HTTP 403.

Challenges and passes are signed with HMAC-SHA256. Each solved challenge can be used only once. Passes can be tied to the visitor's network (/24 for IPv4, /64 for IPv6) and browser, so a copied cookie doesn't work elsewhere.

---

## 🚀 Quick start

### 🐳 Docker

Download one of the two compose files (see [Compose](#-compose)) into an empty folder, then:

```bash
mkdir data
sudo chown 65532:65532 data   # Linux only: the container runs as uid 65532
docker compose up -d
```

| URL | What |
| --- | --- |
| <http://localhost:8923> | Your site, protected |
| <http://localhost:8081> | Admin web UI (web UI version only) |

The first person to open the web UI creates the login, so open it right away — or set `TAMAMO_ADMIN_USERNAME` and `TAMAMO_ADMIN_PASSWORD` beforehand. Point `TAMAMO_TARGET` in `docker-compose.yml` at your application.

The `./data` folder is mounted as `/data` in the container, so you can edit `data/tamamo.yaml` and see `data/tamamo.db` from the host.

Without Compose the backend runs alone, with no web UI (publish only the site port):

```bash
docker run -d -p 8923:8923 \
  -e TAMAMO_TARGET=http://host.docker.internal:3000 \
  -v "$(pwd)/data:/data" tamamo/tamamo:latest
```

### 🧩 Compose

There are two ready compose files, published with the docs (`docs/docs/public/compose/`):

| File | Services | Configure with |
| --- | --- | --- |
| `docker-compose.yml` | `tamamo` (+ an example `app`) | `data/tamamo.yaml` only; the admin API is off |
| `docker-compose.webui.yml` | `tamamo`, `webui` (+ `app`) | the web UI at `:8081`, or `data/tamamo.yaml` |

Both use the public images `tamamo/tamamo` and `tamamo/tamamo-webui`. In the web UI version `tamamo` runs with `TAMAMO_ENABLE_API=true`; its admin API listens on `8081` **inside the compose network only**. The `webui` container sends `/api` to `http://tamamo:8081` by default and resolves the name through Docker's DNS on every request, so it needs no configuration and survives the backend being recreated. Set `TAMAMO_API` on it only if you rename the service.

Switching between them keeps everything: both use the same `./data` folder and the web UI writes the same `tamamo.yaml`.

### 🖥️ Binary

```bash
go build -o tamamo ./cmd/tamamo
TAMAMO_TARGET=http://localhost:3000 ./tamamo -data ./data
```

---

## ⚙️ Configuration

### Environment variables

These override `tamamo.yaml`. A setting fixed by one of them shows as read-only in the web UI.

| Variable | Description | Default |
| --- | --- | --- |
| `TAMAMO_TARGET` | Site Tamamo protects (`http://app:3000`, `https://…`, `unix:///run/app.sock`) | `http://localhost:3000` |
| `TAMAMO_LISTEN` | Address visitors connect to | `:8923` |
| `TAMAMO_ENABLE_API` | `true` turns on the admin API the web UI talks to; anything else keeps it off | off |
| `TAMAMO_ADMIN_LISTEN` | Address of the admin API | `:8081` |
| `TAMAMO_ADMIN_USERNAME` / `TAMAMO_ADMIN_PASSWORD` | Admin login (both or neither, password ≥ 8 characters). Applied on every start; the web UI can't change it while set | – |
| `TAMAMO_ADMIN_TRUSTED_PROXIES` | Proxies in front of the admin API whose `X-Forwarded-For` says who is signing in: IPs, CIDR ranges or `private`. The compose file with the web UI sets `private` | none |
| `TAMAMO_ADMIN_DOMAIN` | Host names the admin API answers on, comma-separated (`admin.example.com`, `*.example.com`) | any host |
| `TAMAMO_DATA` | Folder for `tamamo.yaml`, `tamamo.db`, `secret.key` and uploads | `./data` (`/data` in Docker) |
| `TAMAMO_IP_SOURCE` | Visitor IP source: `remote`, `x-forwarded-for`, `x-real-ip`, `cf-connecting-ip` | `remote` |
| `TAMAMO_DIFFICULTY` | Starting difficulty, read only on the very first start | `4` |

### Files

| What | Where |
| --- | --- |
| Every setting: server, protection, rules, checking page, sites, modules, admin, stats | `data/tamamo.yaml` |
| Statistics | `data/tamamo.db` (SQLite) |
| Signing key (deleting it signs every visitor out) | `data/secret.key` |
| Mascot, background and favicon images | `data/uploads/<slot>.<ext>` — `checking`, `success`, `denied`, `background`, `favicon` |
| Files a module keeps | `data/modules/<name>/` |

`tamamo.yaml` is the one settings file. Every setting is commented in it, and the web UI edits the same file. Tamamo checks it every 2 seconds and applies changes without a restart (`settings reloaded from disk` in the log). A file with a mistake is reported with its line number and the previous settings stay in place. Listen addresses and turning the admin API on or off still need a restart.

### Command line

```bash
tamamo -check                 # validate data/tamamo.yaml, change nothing
tamamo -set-login admin       # password from TAMAMO_ADMIN_PASSWORD, or typed on stdin
tamamo -rotate-secret         # new signing secret (signs every visitor out)
tamamo -modules               # the modules compiled into this build, with their settings
tamamo -version
```

All of them take `-data <dir>`. A running Tamamo picks the change up within a few seconds. In Docker:

```bash
docker compose exec -e TAMAMO_ADMIN_PASSWORD='long password here' tamamo tamamo -set-login admin
```

### Configuring without the web UI

Use `docker-compose.yml` (or leave out `TAMAMO_ENABLE_API`) and edit `data/tamamo.yaml` directly. Sites are listed by name, with their hosts and only the settings that differ from the global ones:

```yaml
server:
  target: http://app:80
sites:
  - name: Blog
    hosts: [blog.example.com]
    target: http://blog:8080
    protection:
      difficulty: 5
    rules:
      - name: Block everything
        action: block
page:
  language: auto   # or en / ru / uk to force the checking-page language
```

Save the file and Tamamo applies it within about 2 seconds. Run `tamamo -check` (or `docker compose exec tamamo tamamo -check`) to validate it first.

---

## 🛡️ Protection settings

In `tamamo.yaml` these live under `protection:`, and each site can override them under its own `protection:`.

| Setting | Meaning |
| --- | --- |
| `enabled` | Off = Tamamo just forwards everything, like a plain reverse proxy |
| `difficulty` | 1–8. Each step is 16× more work. 3–4 is barely noticeable; 6+ makes phones wait |
| `default_action` | What happens to requests no rule matches: `allow`, `challenge` or `block` |
| `pass_hours` | How long a visitor stays verified |
| `challenge_minutes` | How long a visitor has to finish the check |
| `bind_ip` / `bind_user_agent` | Tie the pass to the visitor's network and browser |
| `cookie_name` / `cookie_domain` | Set a domain like `example.com` to share one pass across subdomains |
| `max_failures_per_minute` | Wrong answers allowed per IP per minute before Tamamo slows them down |

### Checks before the rules

These are regular settings under `protection:`, not modules. They run on every request before the rules, in this order.

| Setting | Meaning |
| --- | --- |
| `bypass_headers` | A request that carries a secret header you chose skips the check (uptime monitors, your own scripts) |
| `rate_limit` | More than N requests per window from one address is challenged or blocked |
| `webhooks` | Tamamo asks an HTTP service of yours about each request; it answers allow, challenge, block or nothing |

```yaml
protection:
  bypass_headers:
    - name: Uptime monitor
      header: X-Monitor-Token
      value: a-long-random-value
  rate_limit:
    enabled: true
    requests: 300
    window_seconds: 60
    action: challenge
  webhooks:
    - name: Reputation
      enabled: true
      url: http://checker:9000/check
```

`protection:` also takes three optional lists and switches:

| Setting | Meaning |
| --- | --- |
| `unprotected_paths` | Pages that are never checked at all, e.g. `[/robots.txt, /.well-known/*]`. Nothing runs for them: no rate limit, webhook, module or rule |
| `verified_bots` | `{enabled: true, action: block}` confirms by reverse DNS that a visitor calling itself Googlebot, Bingbot, Yandex, Baiduspider, Applebot, PetalBot or MojeekBot really is one. Fakes get the action |
| `accept_passes_from` | Sites whose visitors need no second check here. For an API on another domain: the page gets a token from `/.tamamo/api/pass` and sends it in the `X-Tamamo-Pass` header |

### Server

Under `server:` in `tamamo.yaml`.

| Setting | Meaning |
| --- | --- |
| `target` | Where verified traffic goes when a site doesn't set its own target |
| `ip_source` | `remote`, `x-forwarded-for`, `x-real-ip` or `cf-connecting-ip`. Use a header only behind a proxy you control |
| `trusted_proxies` | Proxies allowed to set that header. Empty = any peer, only safe when Tamamo can't be reached directly |
| `preserve_host` | Send the original `Host` header to your site |
| `auth_endpoints` | `auto` (default), `on` or `off`: whether `/.tamamo/auth` and `/.tamamo/forward-auth` answer. `auto` means only while `target` is empty |
| `insecure_skip_verify` | Accept a self-signed certificate on the target |

---

## 📜 Rules

Rules are checked top to bottom and the first match wins. A rule matches when **all** of its conditions match; within one condition, **any** line can match.

| Condition | Example | How it matches |
| --- | --- | --- |
| Paths | `/api/*` | the whole path, `*` is a wildcard |
| User agents | `*GPTBot*` | anywhere in the user agent, case-insensitive |
| IPs | `10.0.0.0/8`, `203.0.113.7` | address or CIDR range |
| Methods | `POST` | exact |
| Hosts | `*.example.com` | the whole host name |
| Headers | `Accept-Language: *de*` | anywhere in the header value |

Start any pattern with `re:` to use a regular expression, e.g. `re:^/(admin|login)`.

### Default rules

1. **Allow robots.txt and well-known files** — `/robots.txt`, `/.well-known/*`, `/favicon.ico`
2. **Allow AI assistants** — ChatGPT, Claude, Perplexity, Gemini Deep Research and others fetching pages for a user
3. **Allow Google tools** — Search Console, Lighthouse, PageSpeed Insights, Google's specialized crawlers
4. **Allow archives and other crawlers** — Internet Archive, Arquivo.pt, Firecrawl, Crawl4AI and others
5. **Allow search engines** — Google, Bing, DuckDuckGo, Apple, Yandex, Baidu, Seznam, Mojeek and others
6. **Allow link previews** — Facebook, LinkedIn, Slack, X/Twitter, Pinterest and others
7. **Allow Telegram** — Telegram's link preview bot
8. **Check everyone else**

> ⚠️ User agents can be faked. A scraper pretending to be Googlebot gets through these rules; if that matters, turn the rule off or replace it with IP ranges.

### Rules in `tamamo.yaml`

Global rules live under `rules:`. A site's own rules go under that site's `rules:` and replace the global ones for its hosts. Sites without their own `rules:` use the global list.

```yaml
rules:
  - name: Allow robots.txt and well-known files
    action: allow            # allow | challenge | block
    note: robots.txt, /.well-known/ and the favicon are always reachable.
    paths: [/robots.txt, /.well-known/*, /favicon.ico]
  - name: Check everyone else
    action: challenge
    difficulty: 0            # optional; 0 = the site's difficulty
    enabled: true            # optional; default true
    paths: ["*"]
```

Rule keys: `name`, `enabled`, `action`, `difficulty`, `note`, and the conditions `paths`, `user_agents`, `ips`, `methods`, `hosts` and `headers` (a map like `{Accept-Language: "*de*"}`). A rule matches when all of its conditions match. Rules need no ID.
---

## 🌐 Multiple sites

One Tamamo can protect many sites. Each is picked by host name (`blog.example.com` or `*.example.com`) and can have its own **target**, **protection settings**, **rules** and **checking page**. Anything a site doesn't customize follows the global settings. Hosts no site claims use the **default site**. A pass for one site doesn't work on another.

Sites are listed under `sites:` in `tamamo.yaml` by name, with only what differs from the global settings:

```yaml
sites:
  - name: Blog
    hosts: [blog.example.com]
    target: http://blog:2368
    protection:
      difficulty: 5
      default_action: challenge
      pass_hours: 24
    rules:
      - name: Block everything
        action: block
    page:
      title: Blog
```

---

## 🧩 Modules

A module is a Go package compiled into the `tamamo` binary. It registers itself with the SDK in [`module/`](module/module.go) and can:

- decide about requests (`Checker`) and watch decisions (`Observer`)
- edit proxied requests and responses (`RequestModifier`, `ResponseModifier`)
- add markup, styles and scripts to the checking page (`PageExtender`)
- serve its own URLs to visitors (`Handler`) and its own admin API (`AdminHandler`)
- run background work (`Starter`, `Stopper`)
- declare settings, which the web UI turns into a form, and ship its own pages for the web UI

The standard image contains no modules. Build a Tamamo that includes some with [`cmd/tamamo-build`](cmd/tamamo-build):

```bash
go install github.com/foxgirlsorg/tamamo/cmd/tamamo-build@latest
tamamo-build --with github.com/you/your-module          # a published module
tamamo-build --with github.com/you/your-module=./local  # a folder on disk
```

Or with Docker: `docker build --build-arg MODULES="github.com/you/your-module" -t my-tamamo .`

Then switch the module on under `modules:` in `tamamo.yaml`, or in the web UI under **Configure > Modules**:

```yaml
modules:
  - name: hello
    module: hello
    enabled: true
    settings:
      blocked_paths: [/wp-admin]
```

[`examples/hello`](examples/hello) is a complete module that uses most of the hooks. `tamamo -modules` lists what a build contains.

---

## 🎨 Checking page

Everything on the checking page can be changed — in the web UI's **Checking page** designer with a live preview, or under `page:` in `tamamo.yaml`: texts for each state (checking, success, denied, error), light and dark colors, font, layout (card, split, minimal), mascot position, size and animation, background (solid, dots, grid, stripes or an image), progress style, timings, translations and custom CSS.

The **"Protected by Tamamo"** line at the bottom always stays visible.

### Mascot

Default mascots ship in `web/mascot/`: `checking.png`, `success.png` and `denied.png` (512×512, transparent). Replace them from the web UI or by dropping files named after the slot into `data/uploads/`, e.g. `data/uploads/checking.png`. The `background` and `favicon` slots work the same way.

---

## 🖥️ Admin API and web UI

The backend serves only the **admin API**: JSON under `/api/*`, on `admin.listen` (`:8081`). It serves no HTML. Its only other responses are the static files the checking-page preview loads (`/assets/img/<slot>`, `/assets/modules/`, `/assets/challenge/`, `/assets/mascot/`); every other path gets a small JSON 404. `GET /` answers `{"name":"tamamo","admin_api":true,"version":...}`.

The web UI is a separate project, [`tamamo_webui`](../tamamo_webui), shipped as its own container. It is optional: it proxies `/api` and the asset paths to the API and never touches the proxy itself.

| Topic | Details |
| --- | --- |
| Turning the API off | Leave `TAMAMO_ENABLE_API` unset (or not `true`) and restart. Protection keeps running |
| Admin domains | `admin: domains:` in `tamamo.yaml` or `TAMAMO_ADMIN_DOMAIN`. Plain host names or `*.example.com`, no scheme or port. Other hosts get an empty 404 |
| Sign-in cookie | `HttpOnly`, `SameSite=Strict`, `Secure` over HTTPS (direct or via `X-Forwarded-Proto`). The token never appears in a response body |
| CSRF | Every non-GET request needs the header `X-Tamamo-Request: 1`, and a cross-origin `Origin` is refused |

```yaml
admin:
  domains: [admin.example.com]
```

If you set `admin.domains`, the web UI's proxy must forward the browser's `Host` header to the API (`proxy_set_header Host $host`), or the API's host check refuses it.

---

## 🔁 How the plain reverse proxy mode works

Tamamo listens on `:8923` in front of your app, and visitors connect to it directly or through a proxy you run in front.

1. Every request is matched to a site by its `Host` header. If no site claims the host, the global settings apply.
2. Bypass headers, the rate limit, webhooks and modules run first, then the rules top to bottom. The first one that decides wins: **allow**, **challenge** or **block**. If nothing decides, `protection.default_action` applies.
3. Allowed requests and requests with a valid pass cookie are forwarded to the site's `target`, or `server.target` if the site has none. Streaming responses and websockets work. Tamamo adds `X-Forwarded-For`, `X-Forwarded-Proto` and `X-Forwarded-Host`.
4. Any other request gets the checking page, in place, on the same URL (a 401-style challenge). The browser solves a SHA-256 proof of work in a web worker and posts it to `/.tamamo/api/verify`. It receives an HttpOnly pass cookie, bound to the visitor's IP network and user agent and valid for `pass_hours`, and is sent back to the original URL.
5. Blocked requests get the denied page with HTTP 403.

Contrast this with [auth mode](#-behind-another-proxy): there your proxy serves the app itself and only asks Tamamo about each request.

## 🔀 Behind another proxy

### nginx `auth_request` (when nginx already serves your sites)

nginx keeps serving your site and asks Tamamo about each request. Tamamo answers `204` (let it through), `401` (show the checking page) or `403` (show the denied page), and renders that page when nginx hands the request over. Your app never sees unverified traffic.

A complete, commented server block is in [`deploy/nginx/tamamo.conf`](deploy/nginx/tamamo.conf); the web UI also generates one per site under **Sites > Use with a proxy**. The key parts:

```nginx
location /.tamamo/      { proxy_pass http://tamamo; ... }   # scripts, images, verify
location = /.tamamo/auth { return 404; }                     # visitors can't ask for a verdict
location = /.tamamo-auth { internal; proxy_pass http://tamamo/.tamamo/auth; ... }
location @tamamo        { proxy_pass http://tamamo; proxy_set_header X-Tamamo-Render 1; ... }
location / {
    auth_request /.tamamo-auth;
    error_page 401 403 = @tamamo;
    proxy_pass http://your-app;
}
```

Set `ip_source` to `x-real-ip` and add nginx's address to `trusted_proxies`. Leave `server.target` empty: the two auth endpoints only answer while it is empty, unless you set `server.auth_endpoints: "on"`.

To try it, [`deploy/nginx/docker-compose.yml`](deploy/nginx/docker-compose.yml) runs nginx, Tamamo and two example sites:

```bash
cd deploy/nginx && docker compose up -d --build
```

### Caddy `forward_auth` and Traefik ForwardAuth

Both hand the auth server's answer straight to the visitor, so they use their own endpoint, `GET /.tamamo/forward-auth`. It answers `204` (let it through), or the checking page with `401`, or the denied page with `403`. It reads the page asked for from `X-Forwarded-Uri` and `X-Forwarded-Method`, which the proxy sets itself. Everything under `/.tamamo/` must also be routed to Tamamo.

```
example.com {
    handle /.tamamo/* {
        @verdict path /.tamamo/auth /.tamamo/forward-auth
        respond @verdict 404
        reverse_proxy tamamo:8923
    }
    handle {
        forward_auth tamamo:8923 {
            uri /.tamamo/forward-auth
        }
        reverse_proxy app:80
    }
}
```

For Traefik, route ``Host(`example.com`) && PathPrefix(`/.tamamo/`) && !Path(`/.tamamo/forward-auth`)`` to Tamamo and put a middleware with `forwardauth.address=http://tamamo:8923/.tamamo/forward-auth` on your app's router. Set `ip_source` to `x-forwarded-for` and add the proxy to `trusted_proxies`. Traefik sends the visitor's host name in `X-Forwarded-Host`, which Tamamo reads only from a trusted proxy.

### Reverse proxy

```
visitor → nginx, Caddy or Traefik (TLS) → Tamamo :8923 → your app
```

```nginx
location / {
    proxy_pass http://127.0.0.1:8923;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection $http_connection;
}
```

With Caddy this is `reverse_proxy 127.0.0.1:8923`. With Traefik, point a router at the `tamamo` service, port `8923`.

### Reserved paths

Everything under `/.tamamo/` (scripts, images, the verify endpoint and `/.tamamo/health`) is answered by Tamamo itself and never reaches your site.

---

## 🗂️ Layout

```
tamamo/
|  cmd/tamamo/        | Entry point of the standard build
|  cmd/tamamo-build/  | Builds a Tamamo with extra modules compiled in
|  app/               | The program itself: flags, start-up (a custom build calls app.Main)
|  module/            | The module SDK that modules import
|  internal/
|  |  admin/          | Admin JSON API, sessions, login
|  |  assets/         | Uploaded images
|  |  checks/         | Bypass headers, rate limit, webhooks
|  |  config/         | Settings, rules, tamamo.yaml, hot reload
|  |  core/           | Proof of work, signing, client IP
|  |  modules/        | Runs module instances; the UI kit for module pages
|  |  page/           | Checking page rendering
|  |  server/         | Request handling, proxy, verify endpoint
|  |  stats/          | Counters and recent events
|  examples/hello/    | Example module
|  web/
|  |  challenge/      | Checking page, solver and worker
|  |  mascot/         | Default mascot images
|  deploy/nginx/      | nginx configs and a demo compose file
```

---

## 🧑‍💻 Development

Run the backend with its admin API on `:8081` (the default), then the web UI against it:

```bash
# terminal 1: the backend (no Docker needed)
go run ./cmd/tamamo -data ./data        # with TAMAMO_TARGET=http://localhost:3000 if your app isn't on :3000

# terminal 2: the web UI, from the tamamo_webui repo
cd ../tamamo_webui
npm run dev                              # Vite proxies /api and /assets to http://localhost:8081
```

Open the URL Vite prints. Tests for the backend: `go test ./...`. The admin API's tests are in `internal/admin`.

---

## 🙏 Credits

Tamamo was inspired by [Anubis](https://github.com/TecharoHQ/anubis) by Techaro (MIT). Several of Tamamo's tests are adapted from Anubis' test suite.

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.
