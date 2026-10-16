package config

import (
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Translations maps a language code to the page's words in that language.
type Translations map[string]PageTranslation

// UnmarshalYAML merges the file's entries into the existing map, field by
// field, so a file only has to list the words it changes. A built-in
// language can be removed with "ru: off".
func (t *Translations) UnmarshalYAML(n *yaml.Node) error {
	n = deref(n)
	if isNull(n) {
		return nil
	}
	if n.Kind != yaml.MappingNode {
		return errAt(n, "translations must map a language code to its texts, like {de: {title: ...}}")
	}
	if *t == nil {
		*t = Translations{}
	}
	builtin := DefaultTranslations()
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := deref(n.Content[i]), deref(n.Content[i+1])
		code := strings.ToLower(strings.TrimSpace(k.Value))
		if v.Kind == yaml.ScalarNode && (isNull(v) || oneOf(strings.ToLower(v.Value), "off", "false", "no")) {
			delete(*t, code)
			continue
		}
		base, ok := (*t)[code]
		if !ok {
			base = builtin[code]
		}
		if err := checkKeys(v, typeOf[PageTranslation](), "translations."+code); err != nil {
			return err
		}
		if err := v.Decode(&base); err != nil {
			return yamlError(err)
		}
		(*t)[code] = base
	}
	return nil
}

// DefaultTranslations are the checking page's built-in texts in other
// languages. Add a language by adding an entry here (or in the web UI).
func DefaultTranslations() Translations {
	return Translations{
		"ru": {
			Title: "Секундочку…",
			Texts: PageTexts{
				Checking: StateText{
					Heading: "Проверяем, что вы не бот",
					Message: "Tamamo проверяет ваш браузер перед входом на {host}. Это займёт пару секунд и нужно только один раз.",
				},
				Success: StateText{
					Heading: "Всё в порядке, проходите!",
					Message: "Спасибо, что подождали. Переходим на {host}…",
				},
				Denied: StateText{
					Heading: "Доступ запрещён",
					Message: "Ваш запрос заблокирован правилами защиты {host}. Если это ошибка, свяжитесь с владельцем сайта.",
				},
				Error: StateText{
					Heading: "Что-то пошло не так",
					Message: "Проверка не завершилась. Убедитесь, что JavaScript и cookies включены, и попробуйте ещё раз.",
				},
			},
			RetryLabel:    "Попробовать снова",
			ContinueLabel: "Продолжить",
			NoScript:      "Включите JavaScript, чтобы продолжить. Этот сайт использует короткую проверку proof-of-work, чтобы не пускать ботов.",
			Labels:        ruLabels(),
		},
		"uk": {
			Title: "Хвилинку…",
			Texts: PageTexts{
				Checking: StateText{
					Heading: "Перевіряємо, що ви не бот",
					Message: "Tamamo перевіряє ваш браузер перед входом на {host}. Це займе кілька секунд і потрібно лише один раз.",
				},
				Success: StateText{
					Heading: "Усе гаразд, проходьте!",
					Message: "Дякуємо, що зачекали. Переходимо на {host}…",
				},
				Denied: StateText{
					Heading: "Доступ заборонено",
					Message: "Ваш запит заблоковано правилами захисту {host}. Якщо це помилка, зверніться до власника сайту.",
				},
				Error: StateText{
					Heading: "Щось пішло не так",
					Message: "Перевірка не завершилася. Переконайтеся, що JavaScript і cookies увімкнені, та спробуйте ще раз.",
				},
			},
			RetryLabel:    "Спробувати ще раз",
			ContinueLabel: "Продовжити",
			NoScript:      "Увімкніть JavaScript, щоб продовжити. Цей сайт використовує коротку перевірку proof-of-work, щоб не пускати ботів.",
			Labels:        ukLabels(),
		},
	}
}

func validateTranslations(pg *Page) error {
	fillLabels(&pg.Labels)
	if pg.Translations == nil {
		pg.Translations = Translations{}
	}
	builtin := DefaultTranslations()
	for code, tr := range pg.Translations {
		norm := strings.ToLower(strings.TrimSpace(code))
		if !langTag.MatchString(norm) {
			return fmt.Errorf("translation language %q must be a code like ru, uk or pt-br", code)
		}
		if len(tr.Title) > 200 {
			return fmt.Errorf("translation %s: page title is too long", norm)
		}
		// Built-in languages get the built-in labels for any left empty, so
		// configs saved before labels existed are translated too.
		if def, ok := builtin[norm]; ok {
			tr.Labels = def.Labels.Over(tr.Labels)
		}
		capLabels(&tr.Labels)
		pg.Translations[code] = tr
		if norm != code {
			delete(pg.Translations, code)
			pg.Translations[norm] = tr
		}
	}
	return nil
}

// validateLanguage settles Language and keeps AutoLanguage in step with it.
// Configs written before Language existed take it from AutoLanguage.
func validateLanguage(pg *Page) error {
	l := strings.ToLower(strings.TrimSpace(pg.Language))
	if l == "" {
		l = "auto"
		if !pg.AutoLanguage {
			l = strings.ToLower(pg.Lang)
		}
	}
	if l != "auto" && l != strings.ToLower(pg.Lang) {
		if _, ok := pg.Translations[l]; !ok {
			codes := []string{"auto", strings.ToLower(pg.Lang)}
			for c := range pg.Translations {
				codes = append(codes, c)
			}
			sort.Strings(codes[2:])
			return fmt.Errorf("page language %q has no texts; use one of %s", pg.Language, strings.Join(codes, ", "))
		}
	}
	pg.Language = l
	pg.AutoLanguage = l == "auto"
	return nil
}

// Language is one entry of a page's available languages.
type Language struct {
	Code string
	T    PageTranslation
}

// PickLanguage chooses the page language for an Accept-Language header.
// It returns "" when the page's main texts should be used.
func (p *Page) PickLanguage(acceptLanguage string) string {
	main := strings.ToLower(p.Lang)
	if l := strings.ToLower(p.Language); l != "" && l != "auto" {
		if _, ok := p.Translations[l]; ok && l != main {
			return l
		}
		return ""
	}
	if (p.Language == "" && !p.AutoLanguage) || len(p.Translations) == 0 {
		return ""
	}
	type cand struct {
		tag string
		q   float64
	}
	var cs []cand
	for i, part := range strings.Split(acceptLanguage, ",") {
		tag, params, _ := strings.Cut(strings.TrimSpace(part), ";")
		tag = strings.ToLower(strings.TrimSpace(tag))
		if tag == "" || tag == "*" {
			continue
		}
		q := 1.0
		if v, ok := strings.CutPrefix(strings.TrimSpace(params), "q="); ok {
			if _, err := fmt.Sscanf(v, "%g", &q); err != nil {
				q = 0
			}
		}
		cs = append(cs, cand{tag, q - float64(i)*1e-6})
	}
	sort.SliceStable(cs, func(a, b int) bool { return cs[a].q > cs[b].q })
	for _, c := range cs {
		if c.q <= 0 {
			continue
		}
		for _, t := range []string{c.tag, strings.SplitN(c.tag, "-", 2)[0]} {
			if t == main || strings.SplitN(main, "-", 2)[0] == t {
				return ""
			}
			if _, ok := p.Translations[t]; ok {
				return t
			}
		}
	}
	return ""
}
