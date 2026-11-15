package config

// Defaults returns a working configuration for a fresh install.
func Defaults() *Config {
	return &Config{
		Server: ServerConfig{
			Listen:         ":8923",
			Target:         "http://localhost:3000",
			IPSource:       "remote",
			TrustedProxies: []string{},
			PreserveHost:   true,
			AuthEndpoints:  "auto",
		},
		Sites:   []Site{},
		Modules: []ModuleConfig{},
		Protection: Protection{
			Enabled:          true,
			Difficulty:       4,
			DefaultAction:    ActionChallenge,
			PassHours:        24 * 7,
			ChallengeMinutes: 30,
			BindIP:           true,
			BindUserAgent:    true,
			CookieName:       "tamamo-pass",
			MaxFailures:      30,
			UnprotectedPaths: []string{},
			AcceptPassesFrom: []string{},
			VerifiedBots:     VerifiedBots{Enabled: false, Action: ActionBlock},
			Honeypot:         Honeypot{Enabled: false, Paths: []string{}},
			BypassHeaders:    []BypassHeader{},
			RateLimit: RateLimit{
				Enabled:       false,
				Requests:      120,
				WindowSeconds: 60,
				Action:        ActionBlock,
				IPv6Prefix:    64,
				MaxIPs:        100000,
			},
			Webhooks: []Webhook{},
		},
		Rules: DefaultRules(),
		Page:  DefaultPage(),
		Admin: AdminConfig{
			Listen:         ":8081",
			TrustedProxies: []string{},
			SessionHours:   24 * 7,
		},
		Stats: StatsConfig{
			Enabled:      false, // statistics are only visible in the web UI
			StoreIPs:     true,
			RecentEvents: 200,
		},
	}
}

// AIScraperAgents are user-agent fragments of well-known AI / LLM crawlers.
var AIScraperAgents = []string{
	"*GPTBot*", "*ChatGPT-User*", "*OAI-SearchBot*", "*ClaudeBot*", "*Claude-Web*", "*anthropic-ai*",
	"*CCBot*", "*Bytespider*", "*PerplexityBot*", "*Perplexity-User*", "*Amazonbot*", "*Google-Extended*",
	"*Applebot-Extended*", "*meta-externalagent*", "*FacebookBot*", "*Diffbot*", "*cohere-ai*",
	"*ImagesiftBot*", "*Omgilibot*", "*Timpibot*", "*YouBot*", "*AI2Bot*", "*Ai2Bot-Dolma*",
	"*PetalBot*", "*Scrapy*", "*img2dataset*", "*xAI*", "*GrokBot*",
}

// SearchEngineAgents are user-agent fragments of search-engine crawlers.
var SearchEngineAgents = []string{
	"*Googlebot*", "*bingbot*", "*DuckDuckBot*", "*Applebot*", "*Qwantbot*", "*Kagibot*",
	"*MojeekBot*", "*marginalia*", "*archive.org_bot*", "*YandexBot*",
}

// Bot groups used by the default rules. Each entry matches anywhere in the
// user agent, case-insensitively.
var (
	AIAssistantAgents = wrap("chatgpt-operator", "chatgpt-user", "chatgpt-user-2-0", "claude-code",
		"claude-searchbot", "claude-user", "claude-web", "claudebot", "duckassistbot", "google-extended",
		"oai-searchbot", "perplexitybot", "youbot", "anthropic-ai", "cohere-ai", "amazonbot", "amzn-user",
		"gemini-deep-research")
	GoogleToolAgents = wrap("google-inspectiontool", "googleother", "googleother-image", "googleother-video",
		"googlebot-discovery", "googlebot-image", "googlebot-news", "googlebot-video", "storebot-google",
		"chrome-lighthouse", "google-page-speed-insights")
	ArchiveAgents = wrap("archive-org-bot", "ia-archiver", "ia-archiver-web-archive-org", "amazon-kendra",
		"arquivo-web-crawler", "bravest", "crawl4ai", "firecrawl", "moodlebot", "coccocbot-web", "amzn-searchbot")
	SearchEngineCrawlerAgents = wrap("applebot", "aspiegelbot", "baiduspider", "bingpreview", "bingvideopreview",
		"bingbot", "duckduckbot", "googlebot", "microsoftpreview", "mojeek", "mojeekbot", "petalbot", "seznambot",
		"seznamhomepagecrawler", "slurp", "teoma", "yahoo-blogs", "yahoo-feedseeker", "yahoo-mmcrawler",
		"yahooseeker", "yandex", "yandexadditional", "yandexadditionalbot", "yandexbot")
	SocialAgents = wrap("adidxbot", "baidu", "facebookbot", "linkedinbot", "meta-externalads", "meta-externalagent",
		"meta-externalfetcher", "meta-webindexer", "pinterestbot", "quora-bot", "slackbot", "twitterbot",
		"facebookexternalhit")
)

func wrap(names ...string) []string {
	out := make([]string, len(names))
	for i, n := range names {
		out[i] = "*" + n + "*"
	}
	return out
}

func list(s []string) []string { return append([]string{}, s...) }

// DefaultRules lets well-behaved crawlers, AI assistants and link previews
// through and checks everyone else.
func DefaultRules() []Rule {
	return []Rule{
		{
			ID: "allow-robots-txt", Name: "Allow robots.txt and well-known files", Enabled: true, Action: ActionAllow,
			Note:  "robots.txt, /.well-known/ and the favicon are always reachable.",
			Match: Match{Paths: []string{"/robots.txt", "/.well-known/*", "/favicon.ico"}},
		},
		{
			ID: "allow-ai-crawlers", Name: "Allow AI assistants", Enabled: true, Action: ActionAllow,
			Note:  "ChatGPT, Claude, Perplexity and other assistants fetching pages for their users.",
			Match: Match{UserAgents: list(AIAssistantAgents)},
		},
		{
			ID: "allow-google-tools", Name: "Allow Google tools", Enabled: true, Action: ActionAllow,
			Note:  "Search Console inspection, Lighthouse, PageSpeed Insights and Google's specialized crawlers.",
			Match: Match{UserAgents: list(GoogleToolAgents)},
		},
		{
			ID: "allow-archive-and-other-crawlers", Name: "Allow archives and other crawlers", Enabled: true, Action: ActionAllow,
			Note:  "The Internet Archive, Arquivo.pt and other archiving or indexing crawlers.",
			Match: Match{UserAgents: list(ArchiveAgents)},
		},
		{
			ID: "allow-search-engines", Name: "Allow search engines", Enabled: true, Action: ActionAllow,
			Note:  "Google, Bing, DuckDuckGo, Apple, Yandex, Baidu and other search engines.",
			Match: Match{UserAgents: list(SearchEngineCrawlerAgents)},
		},
		{
			ID: "allow-social-bots", Name: "Allow link previews", Enabled: true, Action: ActionAllow,
			Note:  "Facebook, LinkedIn, Slack, X/Twitter, Pinterest and others building link previews.",
			Match: Match{UserAgents: list(SocialAgents)},
		},
		{
			ID: "allow-telegram", Name: "Allow Telegram", Enabled: true, Action: ActionAllow,
			Note:  "Telegram's link preview bot.",
			Match: Match{UserAgents: []string{"*telegrambot*"}},
		},
		{
			ID: "deny-all-others", Name: "Check everyone else", Enabled: true, Action: ActionChallenge,
			Note:  "Every other request has to pass the check once.",
			Match: Match{Paths: []string{"*"}},
		},
	}
}

func DefaultPage() Page {
	return Page{
		Title: "Just a moment…",
		Lang:  "en",
		Texts: PageTexts{
			Checking: StateText{
				Heading: "Making sure you're not a bot",
				Message: "Tamamo is checking your browser before letting you into {host}. It only takes a moment and happens once.",
			},
			Success: StateText{
				Heading: "All good, you're in!",
				Message: "Thanks for waiting. Taking you to {host} now…",
			},
			Denied: StateText{
				Heading: "Access denied",
				Message: "Your request was blocked by the protection rules of {host}. If you think this is a mistake, contact the site owner.",
			},
			Error: StateText{
				Heading: "Something went wrong",
				Message: "The check couldn't finish. Make sure JavaScript and cookies are enabled, then try again.",
			},
		},
		RetryLabel:    "Try again",
		ContinueLabel: "Continue",
		NoScript:      "Please enable JavaScript to continue. This site uses a short proof-of-work check to keep bots out.",
		FooterText:    "",

		ThemeMode: "dark",
		Light: Palette{
			Background: "#f4f4f5", Surface: "#ffffff", Text: "#18181b", Muted: "#71717a",
			Accent: "#de6161", AccentText: "#ffffff", Border: "#e4e4e7",
			Success: "#16a34a", Danger: "#dc2626",
		},
		Dark: Palette{
			Background: "#0c0c0e", Surface: "#18181b", Text: "#fafafa", Muted: "#a1a1aa",
			Accent: "#e57373", AccentText: "#18181b", Border: "#27272a",
			Success: "#4ade80", Danger: "#f87171",
		},

		Font:          "system",
		FontScale:     100,
		HeadingWeight: 700,
		Align:         "center",

		Layout:     "card",
		CardWidth:  520,
		Radius:     16,
		CardBorder: true,
		CardShadow: false,

		MascotShow:      true,
		MascotPosition:  "top",
		MascotSize:      200,
		MascotAnimation: "float",

		Background:    "dots",
		BackgroundDim: 40,

		Progress:       "bar",
		ShowDifficulty: true,
		ShowHashRate:   true,
		ShowElapsed:    true,
		ShowPercent:    false,

		MinDisplayMs:   800,
		SuccessDelayMs: 900,
		AutoRedirect:   true,
		Animations:     true,

		CreditAlign: "center",

		Language:     "auto",
		AutoLanguage: true,
		Translations: DefaultTranslations(),
		Labels:       DefaultLabels(),
	}
}
