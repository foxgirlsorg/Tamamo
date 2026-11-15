package config

const fileHeader = `Tamamo settings.

Everything Tamamo does is set here. The web UI, when it is on, edits this
same file, so you can switch it off at any time and keep working here.
Saved changes are picked up within a few seconds. If something is wrong,
Tamamo logs the line and keeps running with the previous settings.
Check a file without starting Tamamo:  tamamo -check

Settings you leave out keep their defaults, so the smallest working file is
  server:
    target: http://app:80`

// fileComments are written above the matching keys of the settings file.
var fileComments = map[string]string{
	"server":                      "Where Tamamo listens and where visitors who pass are sent.",
	"server.listen":               "Address visitors connect to. In Docker, publish this port (8923).",
	"server.target":               "Your app: http://host:port, https://... or unix:///path/to.sock.\nSites can have their own target. Leave it empty when nginx sends the\ntraffic to your app itself and only asks Tamamo (auth_request).",
	"server.ip_source":            "Where the visitor's IP comes from: remote (the connection itself),\nx-forwarded-for, x-real-ip or cf-connecting-ip. Use a header only behind\na proxy that sets it.",
	"server.trusted_proxies":      "Proxies allowed to set that header, as IPs or ranges like 172.16.0.0/12.\nEmpty trusts any sender, which is only safe if visitors can't reach\nTamamo directly.",
	"server.preserve_host":        "true: your app sees the visitor's Host header. false: it sees the target's.",
	"server.insecure_skip_verify": "Accept any certificate from an https target (self-signed ones).",

	"protection":                         "How visitors are checked. A site can change any of these for itself.",
	"protection.enabled":                 "false lets every request through without a check.",
	"protection.difficulty":              "Work per check, 1-8. Each step is about 16 times more work;\n4 takes a phone well under a second.",
	"protection.default_action":          "What happens to requests no rule matches: allow, challenge or block.",
	"protection.pass_hours":              "How long a passed check lasts, in hours (168 = a week).",
	"protection.challenge_minutes":       "How long a visitor has to finish a check, in minutes.",
	"protection.bind_ip":                 "Tie a pass to the visitor's network (/24 for IPv4, /64 for IPv6).",
	"protection.bind_user_agent":         "Tie a pass to the visitor's browser.",
	"protection.cookie_name":             "Name of the cookie that holds the pass.",
	"protection.cookie_domain":           "Share the pass with subdomains, e.g. example.com. Empty: this host only.",
	"protection.max_failures_per_minute": "Failed checks one IP may make per minute before it is refused\nfor a while. 0 = no limit.",

	"protection.unprotected_paths":  "Pages that are never checked at all: no check, rate limit, webhook,\nmodule or rule runs for them. Patterns as in rules, e.g.\n  [/robots.txt, /.well-known/*, /favicon.ico]",
	"protection.accept_passes_from": "Sites whose visitors need no second check here, by name. For an API on\nanother domain than its website: the page asks /.tamamo/api/pass for a\ntoken and sends it to the API in the X-Tamamo-Pass header.",
	"protection.verified_bots":      "Check by reverse DNS that a visitor calling itself Googlebot, Bingbot,\nYandex, Baiduspider, Applebot, PetalBot or MojeekBot really is one.\nFakes get the action: block or challenge.",

	"protection.honeypot": "Trap pages no real visitor opens. Whoever opens one is banned by IP\naddress on every site with the honeypot on, for ban_hours (0 = as long as\na pass, pass_hours). Patterns as in rules, e.g.\n  {enabled: true, paths: [/wp-login.php, /.env], ban_hours: 0}",

	"protection.bypass_headers": "Requests carrying one of these secret headers skip every check, e.g. an\nuptime monitor:\n  - {name: Monitor, header: X-Monitor-Token, value: a-long-random-secret}",
	"protection.rate_limit":     "Limit how many requests one IP address may make. Past the limit the\naction applies: block or challenge.",
	"protection.webhooks":       "Ask your own server about each request before the rules run. It gets a\nJSON POST and answers {\"action\": \"allow\" | \"challenge\" | \"block\" | \"\"}.\n  - {name: Reputation, enabled: true, url: http://checker:9000/check}",

	"rules": `Rules, checked top to bottom; the first one that matches decides.
  action: allow | challenge | block
  difficulty: harder or easier check for this rule (0 = the usual one)
  enabled: false switches a rule off without deleting it
A rule matches when all of its conditions match; within one condition
any entry may match. Conditions: paths, user_agents, ips (or ranges),
methods, hosts and headers ({Header-Name: pattern}).
Patterns: * is a wildcard (*GPTBot*, /api/*); start with re: for a
regular expression. Paths must match whole and are case-sensitive;
hosts must match whole, user agents and headers anywhere, ignoring case.`,

	"page":                  "The checking page. Everything can be changed except the\n\"Protected by Tamamo\" line.",
	"page.title":            "Browser tab title.",
	"page.lang":             "Language of the texts below.",
	"page.texts":            "Heading and message for each state. {host} becomes the site's host name.",
	"page.theme_mode":       "light, dark or auto (follows the visitor's system).",
	"page.light":            "Colors for the light theme, as #rrggbb.",
	"page.dark":             "Colors for the dark theme.",
	"page.font":             "system, serif, rounded, mono or custom (then name it in custom_font).",
	"page.font_scale":       "Text size in percent, 70-150.",
	"page.align":            "left or center.",
	"page.layout":           "card, split or minimal.",
	"page.mascot_show":      "The mascot pictures. Replace them in the web UI, or put checking.png,\nsuccess.png and denied.png in the uploads folder next to this file.",
	"page.mascot_position":  "top, left, right or bottom.",
	"page.mascot_animation": "none, float, bounce or wiggle.",
	"page.background":       "solid, dots, grid, stripes or image (uploads/background.png).",
	"page.progress":         "bar, ring, dots, spinner or none.",
	"page.min_display_ms":   "Show the page at least this long, so it doesn't flash by (ms).",
	"page.credit_align":     "Where the \"Protected by Tamamo\" line sits: left, center or right.",
	"page.custom_css":       "Extra CSS for the page. It can't hide the credit line.",
	"page.language":         "Which language visitors see: auto picks the visitor's browser language\nwhen there are texts for it; a code (en, ru, uk, ...) always shows that one.",
	"page.translations":     "The page in other languages. ru and uk are built in: list only the words\nyou change, or remove one with \"ru: off\". Add a language like this:\n  de:\n    title: Einen Moment...\n    texts:\n      checking: {heading: ..., message: ...}",
	"page.labels":           "Smaller words: stat labels, units and error messages.",

	"sites": `Websites with settings of their own, picked by the visitor's Host header.
Hosts no site lists use the settings above. In a site, protection and
page list only what differs from the settings above; rules, when given,
replace the rules above for that site.
  - name: Blog
    hosts: [blog.example.com, "*.blog.example.com"]
    target: http://blog:8080
    protection:
      difficulty: 5
    rules:
      - name: Block everything
        action: block`,

	"modules": `Modules: Go modules compiled into this build of Tamamo, run after the
checks above and before the rules. Each entry switches one on.
  name: your name for the entry (a-z, 0-9, dashes)
  module: the module's ID, when it differs from the name
  sites: [] runs it everywhere; otherwise list site names
  on_error: continue | challenge | block, when the module's check fails
  - name: geo
    enabled: true
    settings: {countries: "KP, XX"}
List what this build contains with:  tamamo -modules`,

	"admin":               "The admin API that the optional web UI container talks to. It only runs\nwhen Tamamo is started with TAMAMO_ENABLE_API=true; without it, this file is\nthe only way to change settings.",
	"admin.listen":        "Address of the admin API. In Docker it stays on the compose network: the\nweb UI container reaches it as tamamo:8081. Don't publish it to the internet.",
	"admin.domains":       "Answer only on these host names, e.g. [admin.example.com]. Empty: any.",
	"admin.username":      "The web UI login. Set it with  tamamo -set-login <username>  or the\nTAMAMO_ADMIN_USERNAME / TAMAMO_ADMIN_PASSWORD variables. When empty, the\nfirst person to open the web UI creates it.",
	"admin.session_hours": "How long a web UI sign-in lasts, in hours.",

	"stats":               "Traffic statistics, kept in tamamo.db next to this file. Off by default:\nthey can only be viewed in the web UI (TAMAMO_ENABLE_API=true).",
	"stats.store_ips":     "Keep visitor IPs in the statistics.",
	"stats.recent_events": "How many recent checks and blocks to keep (10-2000).",
}
