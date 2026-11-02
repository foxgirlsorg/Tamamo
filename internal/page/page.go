// Package page renders Tamamo's challenge page: the "checking your browser"
// screen and its success, denied and error states.
package page

import (
	"fmt"
	"html/template"
	"io"
	"strings"
	"sync"

	"github.com/tamamo/tamamo/internal/config"
	"github.com/tamamo/tamamo/web"
)

// Data is the per-request part of the page.
type Data struct {
	State      string // "checking" | "success" | "denied" | "error"
	Host       string
	Preview    bool
	Token      string
	Random     string
	Difficulty int
	Redirect   string
	VerifyURL  string            // e.g. "/.tamamo/api/verify"
	StaticURL  string            // e.g. "/.tamamo/static" -> StaticURL+"/solver.js", StaticURL+"/worker.js"
	Images     map[string]string // slot -> URL: checking, success, denied, background, favicon
	Message    string            // optional override of the current state's message
	// MessageID, when set, overrides the current state's message with the
	// page label of that JSON name (e.g. "upstream_down"), in the page's
	// language. It wins over Message.
	MessageID string
	// Lang is the translation to show (a key of Page.Translations, usually
	// from Page.PickLanguage); "" or an unknown code = the page's main texts.
	Lang string
	// Modules are page modules added to the page, in order.
	Modules []Module
}

// Module is one page module's additions to the page.
type Module struct {
	Name    string
	Head    template.HTML // inserted at the end of <head>
	Body    template.HTML // inserted at the end of <body>, before the credit line
	Styles  []string      // stylesheet URLs
	Scripts []string      // script URLs (loaded with defer)
}

// Translate returns p with the translation lang merged over its texts (empty
// translated fields keep the main ones) and Lang set to lang. It returns p
// itself when lang is "" or not one of p's translations.
func Translate(p *config.Page, lang string) *config.Page {
	if p == nil || lang == "" {
		return p
	}
	tr, ok := p.Translations[lang]
	if !ok {
		return p
	}
	q := *p
	q.Lang = lang
	pick := func(dst *string, v string) {
		if strings.TrimSpace(v) != "" {
			*dst = v
		}
	}
	pick(&q.Title, tr.Title)
	pick(&q.RetryLabel, tr.RetryLabel)
	pick(&q.ContinueLabel, tr.ContinueLabel)
	pick(&q.NoScript, tr.NoScript)
	pick(&q.FooterText, tr.FooterText)
	q.Labels = q.Labels.Over(tr.Labels)
	for _, st := range []struct {
		dst *config.StateText
		src config.StateText
	}{
		{&q.Texts.Checking, tr.Texts.Checking},
		{&q.Texts.Success, tr.Texts.Success},
		{&q.Texts.Denied, tr.Texts.Denied},
		{&q.Texts.Error, tr.Texts.Error},
	} {
		pick(&st.dst.Heading, st.src.Heading)
		pick(&st.dst.Message, st.src.Message)
	}
	return &q
}

// CreditText is the credit line's text content. It cannot be configured.
const CreditText = "Protected by Tamamo"

var (
	tmplOnce sync.Once
	tmpl     *template.Template
	tmplErr  error
)

func load() (*template.Template, error) {
	tmplOnce.Do(func() {
		tmpl, tmplErr = template.ParseFS(web.FS, "challenge/page.html")
	})
	return tmpl, tmplErr
}

var fontStacks = map[string]string{
	"system":  `system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, "Noto Sans", sans-serif`,
	"serif":   `ui-serif, "Iowan Old Style", "Palatino Linotype", Palatino, "Book Antiqua", Georgia, "Noto Serif", serif`,
	"rounded": `ui-rounded, "SF Pro Rounded", "Hiragino Maru Gothic ProN", Quicksand, Comfortaa, Nunito, "Arial Rounded MT Bold", system-ui, sans-serif`,
	"mono":    `ui-monospace, SFMono-Regular, "Cascadia Code", "Source Code Pro", Menlo, Consolas, "DejaVu Sans Mono", monospace`,
}

type stateText struct {
	Heading string `json:"heading"`
	Message string `json:"message"`
}

// script is the JSON handed to solver.js in #tm-data.
type script struct {
	State          string               `json:"state"`
	Preview        bool                 `json:"preview"`
	Host           string               `json:"host"`
	Token          string               `json:"token"`
	Random         string               `json:"random"`
	Difficulty     int                  `json:"difficulty"`
	Redirect       string               `json:"redirect"`
	VerifyURL      string               `json:"verify_url"`
	WorkerURL      string               `json:"worker_url"`
	Texts          map[string]stateText `json:"texts"`
	Images         map[string]string    `json:"images"`
	RetryLabel     string               `json:"retry_label"`
	ContinueLabel  string               `json:"continue_label"`
	MinDisplayMs   int                  `json:"min_display_ms"`
	SuccessDelayMs int                  `json:"success_delay_ms"`
	AutoRedirect   bool                 `json:"auto_redirect"`
	Animations     bool                 `json:"animations"`
	Mascot         bool                 `json:"mascot"`
	Progress       string               `json:"progress"`
	ShowDifficulty bool                 `json:"show_difficulty"`
	ShowHashRate   bool                 `json:"show_hash_rate"`
	ShowElapsed    bool                 `json:"show_elapsed"`
	ShowPercent    bool                 `json:"show_percent"`
	Labels         config.Labels        `json:"labels"`
}

type view struct {
	P          *config.Page
	Lang       string
	Title      string
	State      string
	Heading    string
	Message    string
	ThemeCSS   template.CSS
	CustomCSS  template.CSS
	Favicon    string
	Background string // background image URL (only when Background == "image")
	Mascot     string // current state's mascot URL ("" = no mascot)
	Continue   string
	SolverURL  string
	Difficulty int
	CreditCSS  template.CSS
	Script     script
	Modules    []Module
	Labels     config.Labels
}

func isState(s string) bool {
	switch s {
	case "checking", "success", "denied", "error":
		return true
	}
	return false
}

func mascotSlot(state string) string {
	if state == "error" {
		return "denied"
	}
	return state
}

// Render writes the challenge page for p and d.
func Render(w io.Writer, p *config.Page, d Data) error {
	t, err := load()
	if err != nil {
		return fmt.Errorf("challenge template: %w", err)
	}
	if p == nil {
		def := config.DefaultPage()
		p = &def
	}
	p = Translate(p, d.Lang)
	state := d.State
	if !isState(state) {
		state = "checking"
	}
	host := d.Host
	sub := func(s string) string { return strings.ReplaceAll(s, "{host}", host) }

	texts := map[string]stateText{
		"checking": {sub(p.Texts.Checking.Heading), sub(p.Texts.Checking.Message)},
		"success":  {sub(p.Texts.Success.Heading), sub(p.Texts.Success.Message)},
		"denied":   {sub(p.Texts.Denied.Heading), sub(p.Texts.Denied.Message)},
		"error":    {sub(p.Texts.Error.Heading), sub(p.Texts.Error.Message)},
	}
	msg := d.Message
	if d.MessageID != "" {
		if l := p.Labels.Get(d.MessageID); l != "" {
			msg = l
		}
	}
	if msg != "" {
		st := texts[state]
		st.Message = sub(msg)
		texts[state] = st
	}

	images := map[string]string{}
	if p.MascotShow {
		for _, k := range []string{"checking", "success", "denied"} {
			if u := d.Images[k]; u != "" {
				images[k] = u
			}
		}
		if u := images["denied"]; u != "" {
			images["error"] = u
		}
	}

	static := strings.TrimRight(d.StaticURL, "/")
	if static == "" {
		static = "/.tamamo/static"
	}
	verify := d.VerifyURL
	if verify == "" {
		verify = "/.tamamo/api/verify"
	}
	redirect := d.Redirect
	if redirect == "" {
		redirect = "/"
	}
	diff := d.Difficulty
	if diff < 1 {
		diff = 4
	}
	if diff > 8 {
		diff = 8
	}

	v := view{
		P:          p,
		Lang:       orDefault(p.Lang, "en"),
		Title:      sub(orDefault(p.Title, "Just a moment…")),
		State:      state,
		Heading:    texts[state].Heading,
		Message:    texts[state].Message,
		ThemeCSS:   template.CSS(themeCSS(p)),
		CustomCSS:  template.CSS(customCSS(p.CustomCSS)),
		Favicon:    d.Images["favicon"],
		Mascot:     images[state],
		Continue:   redirect,
		SolverURL:  static + "/solver.js",
		Difficulty: diff,
		CreditCSS:  template.CSS(creditCSS(p)),
		Modules:    d.Modules,
		Labels:     config.DefaultLabels().Over(p.Labels),
		Script: script{
			State: state, Preview: d.Preview, Host: host,
			Token: d.Token, Random: d.Random, Difficulty: diff, Redirect: redirect,
			VerifyURL: verify, WorkerURL: static + "/worker.js",
			Texts: texts, Images: images,
			RetryLabel: p.RetryLabel, ContinueLabel: p.ContinueLabel,
			MinDisplayMs: p.MinDisplayMs, SuccessDelayMs: p.SuccessDelayMs,
			AutoRedirect: p.AutoRedirect, Animations: p.Animations,
			Mascot: p.MascotShow, Progress: p.Progress,
			ShowDifficulty: p.ShowDifficulty, ShowHashRate: p.ShowHashRate,
			ShowElapsed: p.ShowElapsed, ShowPercent: p.ShowPercent,
			Labels: config.DefaultLabels().Over(p.Labels),
		},
	}
	if p.Background == "image" {
		v.Background = d.Images["background"]
	}
	return t.Execute(w, v)
}

func orDefault(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}

// customCSS is a last line of defense: Validate already rejects these.
func customCSS(css string) string {
	if config.CheckCustomCSS(css) != nil {
		return ""
	}
	return css
}

// cssSafe keeps only characters that cannot end a declaration or block.
// Palette values are validated hex colors and the custom font is validated,
// so this only matters for configs that bypassed Validate.
func cssSafe(s string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case ';', '{', '}', '<', '>', '\\', '\n', '\r', '(', ')', '@', '/':
			return -1
		}
		return r
	}, s)
}

func paletteVars(pl config.Palette) string {
	var b strings.Builder
	for _, kv := range [][2]string{
		{"bg", pl.Background}, {"surface", pl.Surface}, {"text", pl.Text}, {"muted", pl.Muted},
		{"accent", pl.Accent}, {"accent-text", pl.AccentText}, {"border", pl.Border},
		{"success", pl.Success}, {"danger", pl.Danger},
	} {
		fmt.Fprintf(&b, "--tm-%s:%s;", kv[0], cssSafe(kv[1]))
	}
	return b.String()
}

func clamp(v, lo, hi int) int {
	return min(max(v, lo), hi)
}

func themeCSS(p *config.Page) string {
	font := fontStacks[p.Font]
	if p.Font == "custom" && strings.TrimSpace(p.CustomFont) != "" {
		font = cssSafe(p.CustomFont) + ", " + fontStacks["system"]
	}
	if font == "" {
		font = fontStacks["system"]
	}
	var b strings.Builder
	fmt.Fprintf(&b, ":root{--tm-font:%s;--tm-scale:%g;--tm-heading-weight:%d;--tm-card-width:%dpx;--tm-radius:%dpx;"+
		"--tm-mascot-size:%dpx;--tm-bg-blur:%dpx;--tm-bg-dim:%g;",
		font, float64(clamp(p.FontScale, 50, 200))/100, clamp(p.HeadingWeight, 100, 900),
		clamp(p.CardWidth, 280, 1400), clamp(p.Radius, 0, 64), clamp(p.MascotSize, 32, 640),
		clamp(p.BackgroundBlur, 0, 60), float64(clamp(p.BackgroundDim, 0, 100))/100)
	switch p.ThemeMode {
	case "dark":
		b.WriteString("color-scheme:dark;" + paletteVars(p.Dark) + "}")
	case "light":
		b.WriteString("color-scheme:light;" + paletteVars(p.Light) + "}")
	default:
		b.WriteString("color-scheme:light dark;" + paletteVars(p.Light) + "}")
		b.WriteString("@media (prefers-color-scheme: dark){:root{" + paletteVars(p.Dark) + "}}")
	}
	return b.String()
}

// creditCSS is the credit line's inline style. Inline !important beats any
// stylesheet rule, so custom CSS cannot hide or shrink it.
func creditCSS(p *config.Page) string {
	color := cssSafe(p.Light.Muted)
	switch p.ThemeMode {
	case "dark":
		color = cssSafe(p.Dark.Muted)
	case "auto":
		color = cssSafe(p.Light.Muted) + " !important;color:light-dark(" + cssSafe(p.Light.Muted) + "," + cssSafe(p.Dark.Muted) + ")"
	}
	scheme := map[string]string{"dark": "dark", "light": "light"}[p.ThemeMode]
	if scheme == "" {
		scheme = "light dark"
	}
	justify := map[string]string{"left": "flex-start", "right": "flex-end"}[p.CreditAlign]
	align := p.CreditAlign
	if justify == "" {
		justify, align = "center", "center"
	}
	return "display:flex !important;align-items:center !important;justify-content:" + justify + " !important;" +
		"gap:6px !important;text-align:" + align + " !important;visibility:visible !important;opacity:1 !important;" +
		"position:relative !important;inset:auto !important;transform:none !important;translate:none !important;" +
		"scale:none !important;rotate:none !important;clip-path:none !important;clip:auto !important;" +
		"mask:none !important;filter:none !important;mix-blend-mode:normal !important;" +
		"content-visibility:visible !important;font-size:13px !important;line-height:1.5 !important;" +
		"font-family:system-ui,-apple-system,\"Segoe UI\",Roboto,sans-serif !important;" +
		"letter-spacing:normal !important;text-indent:0 !important;text-shadow:none !important;" +
		"height:auto !important;min-height:20px !important;max-height:none !important;width:auto !important;" +
		"max-width:none !important;overflow:visible !important;margin:0 !important;padding:14px 20px 18px !important;" +
		"color-scheme:" + scheme + " !important;color:" + color + " !important;" +
		"background:transparent !important;border:0 !important;z-index:2147483647 !important;pointer-events:auto !important;" +
		"order:9999 !important;flex:none !important;float:none !important"
}
