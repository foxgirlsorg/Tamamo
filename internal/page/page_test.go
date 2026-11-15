package page

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/foxgirlsorg/tamamo/internal/config"
)

func images() map[string]string {
	return map[string]string{
		"checking": "/.tamamo/static/mascot/checking.png",
		"success":  "/.tamamo/static/mascot/success.png",
		"denied":   "/.tamamo/static/mascot/denied.png",
		"favicon":  "/.tamamo/static/mascot/checking.png",
	}
}

func data(state string) Data {
	return Data{
		State: state, Host: "example.org", Token: "tok", Random: "abc123", Difficulty: 4,
		Redirect: "/wiki?x=1", VerifyURL: "/.tamamo/api/verify", StaticURL: "/.tamamo/static",
		Images: images(),
	}
}

func render(t *testing.T, p *config.Page, d Data) string {
	t.Helper()
	var b bytes.Buffer
	if err := Render(&b, p, d); err != nil {
		t.Fatalf("Render: %v", err)
	}
	return b.String()
}

var dataRe = regexp.MustCompile(`(?s)<script type="application/json" id="tm-data">(.*?)</script>`)

func scriptData(t *testing.T, html string) map[string]any {
	t.Helper()
	m := dataRe.FindStringSubmatch(html)
	if m == nil {
		t.Fatal("no tm-data block")
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(m[1]), &out); err != nil {
		t.Fatalf("tm-data is not JSON: %v\n%s", err, m[1])
	}
	return out
}

const credit = `<footer class="tm-credit" style="`

func TestRenderMatrix(t *testing.T) {
	for _, state := range []string{"checking", "success", "denied", "error"} {
		for _, layout := range []string{"card", "split", "minimal"} {
			for _, mode := range []string{"light", "dark", "auto"} {
				for _, prog := range []string{"bar", "ring", "dots", "spinner", "none"} {
					p := config.DefaultPage()
					p.Layout, p.ThemeMode, p.Progress = layout, mode, prog
					html := render(t, &p, data(state))
					if !strings.Contains(html, credit) || !strings.Contains(html, "Protected by <strong") {
						t.Fatalf("%s/%s/%s: credit missing", state, layout, mode)
					}
					// The credit must be the last element in <body>.
					tail := html[strings.LastIndex(html, credit):]
					if !strings.HasSuffix(strings.TrimSpace(tail), "</footer>\n</body>\n</html>") &&
						!strings.HasSuffix(strings.TrimSpace(tail), "</footer>\n</body>\n</html>\n") {
						t.Fatalf("%s/%s/%s: credit is not last in body: %q", state, layout, mode, tail[len(tail)-40:])
					}
					if !strings.Contains(html, `data-state="`+state+`"`) {
						t.Fatalf("%s: initial state not rendered", state)
					}
					d := scriptData(t, html)
					if d["state"] != state {
						t.Fatalf("script state = %v", d["state"])
					}
				}
			}
		}
	}
}

func TestHeadAndMeta(t *testing.T) {
	p := config.DefaultPage()
	p.Lang = "de"
	p.ThemeMode = "auto"
	p.Light.Accent = "#de6161"
	html := render(t, &p, data("checking"))
	for _, want := range []string{
		`<html lang="de">`,
		`<meta name="robots" content="noindex, nofollow">`,
		`<meta name="generator" content="Tamamo">`,
		`<meta name="viewport"`,
		`<link rel="icon" href="/.tamamo/static/mascot/checking.png">`,
		`<script src="/.tamamo/static/solver.js" defer>`,
		`<noscript>`,
		p.NoScript,
		`--tm-accent:#de6161;`,
		`@media (prefers-color-scheme: dark)`,
	} {
		if !strings.Contains(html, want) {
			t.Errorf("missing %q", want)
		}
	}
	d := scriptData(t, html)
	if d["worker_url"] != "/.tamamo/static/worker.js" || d["verify_url"] != "/.tamamo/api/verify" {
		t.Errorf("urls: %v %v", d["worker_url"], d["verify_url"])
	}
	if d["redirect"] != "/wiki?x=1" || d["token"] != "tok" || d["random"] != "abc123" || d["difficulty"] != float64(4) {
		t.Errorf("challenge data: %v", d)
	}
}

func TestHostSubstitution(t *testing.T) {
	p := config.DefaultPage()
	html := render(t, &p, data("checking"))
	if strings.Contains(html, "{host}") {
		t.Error("{host} left in output")
	}
	if !strings.Contains(html, "letting you into example.org.") {
		t.Error("host not substituted in message")
	}
	d := scriptData(t, html)
	texts := d["texts"].(map[string]any)
	if !strings.Contains(texts["success"].(map[string]any)["message"].(string), "example.org") {
		t.Error("host not substituted in script texts")
	}
}

func TestEscaping(t *testing.T) {
	p := config.DefaultPage()
	p.Texts.Checking.Heading = `<script>alert(1)</script>`
	p.Texts.Success.Message = `</script><img src=x onerror=alert(1)>`
	p.Title = `</title><script>x</script>`
	p.FooterText = `<b>hi</b>`
	d := data("checking")
	d.Host = `<i>evil</i>.org`
	d.Redirect = `javascript:alert(1)`
	html := render(t, &p, d)
	for _, bad := range []string{"<script>alert(1)", "<img src=x", "</title><script>", "<b>hi</b>", "<i>evil</i>", `href="javascript:`} {
		if strings.Contains(html, bad) {
			t.Errorf("unescaped %q in output", bad)
		}
	}
	if !strings.Contains(html, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Error("heading not HTML-escaped")
	}
	sd := scriptData(t, html)
	if sd["texts"].(map[string]any)["success"].(map[string]any)["message"] != `</script><img src=x onerror=alert(1)>` {
		t.Error("script data did not round-trip")
	}
}

func TestCustomCSSAndTheme(t *testing.T) {
	p := config.DefaultPage()
	p.CustomCSS = ".tm-heading{letter-spacing:-.05em}"
	p.Font = "custom"
	p.CustomFont = `"Inter", sans-serif`
	p.ThemeMode = "dark"
	html := render(t, &p, data("checking"))
	ci := strings.Index(html, p.CustomCSS)
	ti := strings.Index(html, "--tm-accent:")
	if ci < 0 || ti < 0 || ci < ti {
		t.Fatal("custom CSS missing or before theme")
	}
	if !strings.Contains(html, `--tm-font:"Inter", sans-serif,`) {
		t.Error("custom font missing")
	}
	if !strings.Contains(html, "--tm-accent:"+p.Dark.Accent) || strings.Contains(html, "prefers-color-scheme: dark") {
		t.Error("dark mode not applied")
	}
	// CSS that targets the credit is dropped even if Validate was bypassed.
	p.CustomCSS = "footer.tm-credit{display:none}"
	if html := render(t, &p, data("checking")); strings.Contains(html, "display:none}") && strings.Contains(html, "footer.tm-credit{display:none}") {
		t.Error("credit-targeting CSS rendered")
	}
}

func TestStatesAndOptions(t *testing.T) {
	p := config.DefaultPage()
	p.AutoRedirect = false
	html := render(t, &p, data("success"))
	if !regexp.MustCompile(`id="tm-continue" href="/wiki\?x=1">`).MatchString(html) {
		t.Error("continue button not visible on success without auto redirect")
	}
	html = render(t, &p, data("error"))
	if !strings.Contains(html, `id="tm-retry" href="">`) || !strings.Contains(html, `/mascot/denied.png`) {
		t.Error("error state: retry or denied mascot missing")
	}
	d := data("denied")
	d.Message = "Blocked for {host} by rule X"
	html = render(t, &p, d)
	if !strings.Contains(html, "Blocked for example.org by rule X") {
		t.Error("message override missing")
	}
	p.MascotShow = false
	if html := render(t, &p, data("checking")); strings.Contains(html, `id="tm-mascot"`) {
		t.Error("mascot shown although disabled")
	}
	p = config.DefaultPage()
	p.Background = "image"
	d = data("checking")
	d.Images["background"] = "/bg.jpg"
	if html := render(t, &p, d); !strings.Contains(html, `<img src="/bg.jpg" alt="">`) {
		t.Error("background image missing")
	}
	p.FooterText = "Run by the example team"
	p.CreditAlign = "right"
	html = render(t, &p, data("checking"))
	if !strings.Contains(html, "Run by the example team") || !strings.Contains(html, "justify-content:flex-end !important") {
		t.Error("footer text or credit alignment missing")
	}
	// Bad state falls back to checking.
	if html := render(t, nil, Data{State: "bogus"}); !strings.Contains(html, `data-state="checking"`) {
		t.Error("unknown state did not fall back")
	}
}

func TestPreviewFlag(t *testing.T) {
	p := config.DefaultPage()
	d := data("checking")
	d.Preview = true
	html := render(t, &p, d)
	if scriptData(t, html)["preview"] != true || !strings.Contains(html, `data-preview="on"`) {
		t.Error("preview flag missing")
	}
}

const artCreditLink = `<a href="https://t.me/KiwiCR2" target="_blank" rel="noopener noreferrer">Kiwi CR2</a>`

// artCreditInFooter is the art part inside the footer: after "Protected by
// Tamamo", separated by a middle dot, and nothing after it but </footer>.
const artCreditInFooter = `Protected by <strong style="display:inline !important;font-weight:700 !important;color:inherit !important;font-size:inherit !important">Tamamo</strong></span><span class="tm-art"><span class="tm-art-sep" aria-hidden="true">&middot;</span>Art by ` + artCreditLink + `</span></footer>`

func TestMascotArtCredit(t *testing.T) {
	for _, withCredit := range []bool{true, false} {
		for _, show := range []bool{true, false} {
			for _, state := range []string{"checking", "success", "denied", "error"} {
				p := config.DefaultPage()
				p.MascotShow = show
				d := data(state)
				d.MascotCredit = withCredit
				html := render(t, &p, d)

				want := withCredit && show
				if got := strings.Contains(html, "Kiwi CR2"); got != want {
					t.Fatalf("credit=%v show=%v state=%s: art credit present=%v, want %v",
						withCredit, show, state, got, want)
				}
				if got := strings.Contains(html, "Art by "); got != want {
					t.Fatalf("credit=%v show=%v state=%s: \"Art by\" present=%v, want %v",
						withCredit, show, state, got, want)
				}
				if strings.Contains(html, "Mascot Eru") || strings.Contains(html, "tm-art-credit") {
					t.Fatalf("credit=%v show=%v state=%s: old art credit markup still rendered", withCredit, show, state)
				}
				if want && !strings.Contains(html, artCreditInFooter) {
					t.Fatalf("credit=%v show=%v state=%s: art credit must sit inside the footer after the Tamamo credit", withCredit, show, state)
				}
				if !want && strings.Contains(html, "&middot;") {
					t.Fatalf("credit=%v show=%v state=%s: separator rendered without art credit", withCredit, show, state)
				}
				// The Tamamo credit footer must stay a direct child of body, last.
				if !strings.Contains(html, credit) {
					t.Fatalf("state=%s: footer credit missing", state)
				}
				tail := html[strings.LastIndex(html, credit):]
				if !strings.HasSuffix(strings.TrimSpace(tail), "</footer>\n</body>\n</html>") &&
					!strings.HasSuffix(strings.TrimSpace(tail), "</footer>\n</body>\n</html>\n") {
					t.Fatalf("state=%s: footer credit is not last in body", state)
				}
			}
		}
	}
}

func TestDefaultMascots(t *testing.T) {
	cases := []struct {
		custom map[string]bool
		want   bool
	}{
		{map[string]bool{}, true},
		{map[string]bool{"background": true, "favicon": true}, true},
		{map[string]bool{"checking": true}, false},
		{map[string]bool{"success": true}, false},
		{map[string]bool{"denied": true}, false},
	}
	for _, c := range cases {
		if got := DefaultMascots(c.custom); got != c.want {
			t.Errorf("DefaultMascots(%v) = %v, want %v", c.custom, got, c.want)
		}
	}
}

// TestWriteSamples writes sample pages when TAMAMO_PAGE_SAMPLES is set.
func TestWriteSamples(t *testing.T) {
	dir := os.Getenv("TAMAMO_PAGE_SAMPLES")
	if dir == "" {
		t.Skip("TAMAMO_PAGE_SAMPLES not set")
	}
	imgs := map[string]string{"checking": "mascot/checking.png", "success": "mascot/success.png", "denied": "mascot/denied.png", "favicon": "mascot/checking.png"}
	variants := map[string]func(p *config.Page){
		"card":      func(p *config.Page) {},
		"card-left": func(p *config.Page) { p.MascotPosition = "left"; p.Align = "left"; p.CardShadow = true },
		"card-dark": func(p *config.Page) {
			p.ThemeMode = "dark"
			p.Progress = "ring"
			p.ShowPercent = true
			p.Background = "grid"
		},
		"card-bot": func(p *config.Page) { p.MascotPosition = "bottom"; p.Progress = "dots"; p.Background = "stripes" },
		"split": func(p *config.Page) {
			p.Layout = "split"
			p.MascotPosition = "left"
			p.MascotSize = 360
			p.Align = "left"
		},
		"split-top": func(p *config.Page) { p.Layout = "split"; p.Progress = "spinner"; p.FooterText = "Operated by Example" },
		"minimal": func(p *config.Page) {
			p.Layout = "minimal"
			p.Font = "serif"
			p.MascotAnimation = "wiggle"
			p.MascotMirror = true
		},
		"minimal-rt": func(p *config.Page) {
			p.Layout = "minimal"
			p.MascotPosition = "right"
			p.Font = "rounded"
			p.Align = "left"
		},
	}
	for name, fn := range variants {
		for _, state := range []string{"checking", "success", "denied", "error"} {
			p := config.DefaultPage()
			fn(&p)
			d := data(state)
			d.Images = imgs
			d.Preview = true
			d.StaticURL = "."
			var b bytes.Buffer
			if err := Render(&b, &p, d); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, name+"-"+state+".html"), b.Bytes(), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
}
