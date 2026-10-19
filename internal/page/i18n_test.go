package page

import (
	"strings"
	"testing"

	"github.com/tamamo/tamamo/internal/config"
)

func TestTranslate(t *testing.T) {
	p := config.DefaultPage()
	p.Translations["de"] = config.PageTranslation{
		Texts: config.PageTexts{Checking: config.StateText{Heading: "Moment bitte"}},
	}
	ru := config.DefaultTranslations()["ru"]

	d := data("checking")
	d.Lang = "ru"
	html := render(t, &p, d)
	if !strings.Contains(html, `<html lang="ru">`) || !strings.Contains(html, ru.Texts.Checking.Heading) ||
		!strings.Contains(html, ru.Title) || !strings.Contains(html, ru.NoScript) {
		t.Error("ru translation not applied")
	}
	if sd := scriptData(t, html); sd["retry_label"] != ru.RetryLabel {
		t.Errorf("solver texts not translated: %v", sd["retry_label"])
	}

	// Empty translated fields fall back to the main texts.
	d.Lang = "de"
	html = render(t, &p, d)
	if !strings.Contains(html, `<html lang="de">`) || !strings.Contains(html, "Moment bitte") ||
		!strings.Contains(html, strings.ReplaceAll(p.Texts.Checking.Message, "{host}", "example.org")) ||
		!strings.Contains(html, p.NoScript) {
		t.Error("de fallback broken")
	}

	// Unknown or empty: main texts.
	for _, l := range []string{"", "xx"} {
		d.Lang = l
		html = render(t, &p, d)
		if !strings.Contains(html, `<html lang="en">`) || !strings.Contains(html, p.Texts.Checking.Heading) {
			t.Errorf("lang %q: main texts expected", l)
		}
	}
	// Translate must not modify the page it was given.
	if p.Lang != "en" || p.Title == ru.Title {
		t.Error("Translate changed its input")
	}
}

func TestPickLanguage(t *testing.T) {
	p := config.DefaultPage()
	p.Translations["pt-br"] = config.PageTranslation{Title: "Um momento"}
	for al, want := range map[string]string{
		"ru":                    "ru",
		"ru-RU,ru;q=0.9":        "ru",
		"uk-UA":                 "uk",
		"en,ru":                 "",
		"de,ru;q=0.5,uk;q=0.7":  "uk",
		"ru;q=0,uk;q=0.1":       "uk",
		"ru;q=0":                "",
		"pt-BR":                 "pt-br",
		"fr, *;q=0.1":           "",
		"":                      "",
		"en-GB;q=0.8, ru;q=0.9": "ru",
		"uk;q=0.9, ru;q=0.9":    "uk", // equal quality: header order
	} {
		if got := p.PickLanguage(al); got != want {
			t.Errorf("PickLanguage(%q) = %q, want %q", al, got, want)
		}
	}
	// Auto-detection off: Language set to the main language.
	p.Language, p.AutoLanguage = "en", false
	for _, al := range []string{"ru", "uk", "pt-BR", ""} {
		if got := p.PickLanguage(al); got != "" {
			t.Errorf("language en, PickLanguage(%q) = %q, want main texts", al, got)
		}
	}

	// Forced language: shown regardless of Accept-Language.
	p.Language = "ru"
	for _, al := range []string{"", "en-US,en;q=0.9", "uk", "pt-BR,pt;q=0.9", "de,fr;q=0.8", "ru;q=0", "*"} {
		if got := p.PickLanguage(al); got != "ru" {
			t.Errorf("language ru, PickLanguage(%q) = %q, want ru", al, got)
		}
	}
}

func TestLabels(t *testing.T) {
	p := config.DefaultPage()
	p.ShowDifficulty, p.ShowHashRate, p.ShowElapsed, p.ShowPercent, p.Progress = true, true, true, true, "bar"
	p.Translations["de"] = config.PageTranslation{Labels: config.Labels{Speed: "Tempo"}}
	ru := config.DefaultTranslations()["ru"].Labels
	en := config.DefaultLabels()

	d := data("checking")
	d.Lang = "ru"
	html := render(t, &p, d)
	for _, want := range []string{"<dt>" + ru.Difficulty + "</dt>", "<dt>" + ru.Speed + "</dt>", "<dt>" + ru.Time + "</dt>",
		"<dt>" + ru.Progress + "</dt>", "0.0 " + ru.Seconds, `alt="` + ru.MascotAlt + `"`, "Protected by <strong"} {
		if !strings.Contains(html, want) {
			t.Errorf("ru page lacks %q", want)
		}
	}
	labels := scriptData(t, html)["labels"].(map[string]any)
	if labels["cookies_disabled"] != ru.CookiesDisabled || labels["hash_rate_k"] != ru.HashRateK {
		t.Errorf("solver labels %v", labels)
	}

	d.Lang = "de"
	html = render(t, &p, d)
	if !strings.Contains(html, "<dt>Tempo</dt>") || !strings.Contains(html, "<dt>"+en.Difficulty+"</dt>") {
		t.Error("label fallback broken")
	}

	d = data("error")
	d.Lang = "ru"
	d.MessageID = "upstream_down"
	if html = render(t, &p, d); !strings.Contains(html, ru.UpstreamDown) {
		t.Error("MessageID not translated")
	}
	for _, id := range []string{"difficulty", "challenge_used", "upstream_missing", "mascot_alt"} {
		if en.Get(id) == "" || ru.Get(id) == "" || config.DefaultTranslations()["uk"].Labels.Get(id) == "" {
			t.Errorf("label %s missing in a built-in language", id)
		}
	}
}
