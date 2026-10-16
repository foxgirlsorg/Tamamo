package config

import (
	"reflect"
	"strings"
	"unicode/utf8"
)

// Labels are every short text of the checking page besides the state
// headings and messages: stat labels, units, the mascot's alt text and the
// error messages of the solver (solver.js) and the server. All fields are
// plain text. "{error}" and "{status}" are filled in where noted.
//
// The credit line ("Protected by Tamamo") is deliberately not a label: it
// reads the same in every language.
type Labels struct {
	// Stats under the progress bar.
	Difficulty string `json:"difficulty" yaml:"difficulty"`
	Speed      string `json:"speed" yaml:"speed"`
	Time       string `json:"time" yaml:"time"`
	Progress   string `json:"progress" yaml:"progress"`
	// Units.
	Seconds   string `json:"seconds" yaml:"seconds"`         // "s"
	Minutes   string `json:"minutes" yaml:"minutes"`         // "min"
	HashRate  string `json:"hash_rate" yaml:"hash_rate"`     // "H/s"
	HashRateK string `json:"hash_rate_k" yaml:"hash_rate_k"` // "kH/s"
	HashRateM string `json:"hash_rate_m" yaml:"hash_rate_m"` // "MH/s"
	MascotAlt string `json:"mascot_alt" yaml:"mascot_alt"`   // alt text of the mascot image
	// Errors found by the browser (solver.js).
	CookiesDisabled string `json:"cookies_disabled" yaml:"cookies_disabled"`
	BrowserTooOld   string `json:"browser_too_old" yaml:"browser_too_old"`
	DataMissing     string `json:"data_missing" yaml:"data_missing"`
	SolverFailed    string `json:"solver_failed" yaml:"solver_failed"` // {error}
	TooManyAttempts string `json:"too_many_attempts" yaml:"too_many_attempts"`
	NetworkError    string `json:"network_error" yaml:"network_error"`
	ServerRejected  string `json:"server_rejected" yaml:"server_rejected"` // {status}
	// Errors the server answers when checking a solution.
	BadRequest           string `json:"bad_request" yaml:"bad_request"`
	ChallengeInvalid     string `json:"challenge_invalid" yaml:"challenge_invalid"`
	ChallengeWrongSite   string `json:"challenge_wrong_site" yaml:"challenge_wrong_site"`
	ChallengeExpired     string `json:"challenge_expired" yaml:"challenge_expired"`
	ChallengeWrongClient string `json:"challenge_wrong_client" yaml:"challenge_wrong_client"`
	ProofWrong           string `json:"proof_wrong" yaml:"proof_wrong"`
	ChallengeUsed        string `json:"challenge_used" yaml:"challenge_used"`
	// Error page messages.
	UpstreamMissing string `json:"upstream_missing" yaml:"upstream_missing"`
	UpstreamDown    string `json:"upstream_down" yaml:"upstream_down"`
}

// DefaultLabels are the English labels.
func DefaultLabels() Labels {
	return Labels{
		Difficulty: "Difficulty",
		Speed:      "Speed",
		Time:       "Time",
		Progress:   "Progress",
		Seconds:    "s",
		Minutes:    "min",
		HashRate:   "H/s",
		HashRateK:  "kH/s",
		HashRateM:  "MH/s",
		MascotAlt:  "Tamamo mascot",

		CookiesDisabled: "Cookies are turned off in this browser. Tamamo needs a cookie to remember that you passed the check. Please enable cookies for this site and try again.",
		BrowserTooOld:   "This browser is too old to run the check. Please update it and try again.",
		DataMissing:     "The challenge data is missing. Please reload the page.",
		SolverFailed:    "The check could not run in this browser ({error}). Please reload the page.",
		TooManyAttempts: "Too many attempts. Please wait a minute, then try again.",
		NetworkError:    "Could not reach the server. Check your connection and try again.",
		ServerRejected:  "The server rejected the check (HTTP {status}).",

		BadRequest:           "The request could not be read.",
		ChallengeInvalid:     "The challenge is invalid. Please reload the page.",
		ChallengeWrongSite:   "The challenge was issued for a different site. Please reload the page.",
		ChallengeExpired:     "The challenge expired. Please reload the page.",
		ChallengeWrongClient: "The challenge was issued to a different browser or network. Please reload the page.",
		ProofWrong:           "The proof of work is wrong. Please reload the page.",
		ChallengeUsed:        "This challenge was already used. Please reload the page.",

		UpstreamMissing: "No upstream is configured for this site.",
		UpstreamDown:    "The site behind Tamamo isn't responding right now. Please try again in a moment.",
	}
}

func ruLabels() Labels {
	return Labels{
		Difficulty: "Сложность",
		Speed:      "Скорость",
		Time:       "Время",
		Progress:   "Готово",
		Seconds:    "с",
		Minutes:    "мин",
		HashRate:   "хеш/с",
		HashRateK:  "тыс. хеш/с",
		HashRateM:  "млн хеш/с",
		MascotAlt:  "Талисман Tamamo",

		CookiesDisabled: "В этом браузере отключены cookies. Tamamo нужен cookie, чтобы запомнить, что вы прошли проверку. Включите cookies для этого сайта и попробуйте ещё раз.",
		BrowserTooOld:   "Этот браузер слишком старый для проверки. Обновите его и попробуйте ещё раз.",
		DataMissing:     "Не хватает данных проверки. Перезагрузите страницу.",
		SolverFailed:    "Проверка не запустилась в этом браузере ({error}). Перезагрузите страницу.",
		TooManyAttempts: "Слишком много попыток. Подождите минуту и попробуйте снова.",
		NetworkError:    "Не удалось связаться с сервером. Проверьте подключение и попробуйте ещё раз.",
		ServerRejected:  "Сервер отклонил проверку (HTTP {status}).",

		BadRequest:           "Не удалось прочитать запрос.",
		ChallengeInvalid:     "Проверка недействительна. Перезагрузите страницу.",
		ChallengeWrongSite:   "Проверка выдана для другого сайта. Перезагрузите страницу.",
		ChallengeExpired:     "Время проверки истекло. Перезагрузите страницу.",
		ChallengeWrongClient: "Проверка выдана другому браузеру или сети. Перезагрузите страницу.",
		ProofWrong:           "Решение proof-of-work неверно. Перезагрузите страницу.",
		ChallengeUsed:        "Эта проверка уже использована. Перезагрузите страницу.",

		UpstreamMissing: "Для этого сайта не настроен сервер назначения.",
		UpstreamDown:    "Сайт за Tamamo сейчас не отвечает. Попробуйте ещё раз чуть позже.",
	}
}

func ukLabels() Labels {
	return Labels{
		Difficulty: "Складність",
		Speed:      "Швидкість",
		Time:       "Час",
		Progress:   "Готово",
		Seconds:    "с",
		Minutes:    "хв",
		HashRate:   "хеш/с",
		HashRateK:  "тис. хеш/с",
		HashRateM:  "млн хеш/с",
		MascotAlt:  "Талісман Tamamo",

		CookiesDisabled: "У цьому браузері вимкнено cookies. Tamamo потрібен cookie, щоб запам'ятати, що ви пройшли перевірку. Увімкніть cookies для цього сайту та спробуйте ще раз.",
		BrowserTooOld:   "Цей браузер застарий для перевірки. Оновіть його та спробуйте ще раз.",
		DataMissing:     "Бракує даних перевірки. Перезавантажте сторінку.",
		SolverFailed:    "Перевірка не запустилася в цьому браузері ({error}). Перезавантажте сторінку.",
		TooManyAttempts: "Забагато спроб. Зачекайте хвилину й спробуйте знову.",
		NetworkError:    "Не вдалося зв'язатися із сервером. Перевірте з'єднання та спробуйте ще раз.",
		ServerRejected:  "Сервер відхилив перевірку (HTTP {status}).",

		BadRequest:           "Не вдалося прочитати запит.",
		ChallengeInvalid:     "Перевірка недійсна. Перезавантажте сторінку.",
		ChallengeWrongSite:   "Перевірку видано для іншого сайту. Перезавантажте сторінку.",
		ChallengeExpired:     "Час перевірки сплив. Перезавантажте сторінку.",
		ChallengeWrongClient: "Перевірку видано іншому браузеру або мережі. Перезавантажте сторінку.",
		ProofWrong:           "Розв'язок proof-of-work неправильний. Перезавантажте сторінку.",
		ChallengeUsed:        "Цю перевірку вже використано. Перезавантажте сторінку.",

		UpstreamMissing: "Для цього сайту не налаштовано сервер призначення.",
		UpstreamDown:    "Сайт за Tamamo зараз не відповідає. Спробуйте ще раз трохи згодом.",
	}
}

// Get returns the label with JSON name id ("challenge_used"), or "".
func (l Labels) Get(id string) string {
	v := reflect.ValueOf(l)
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		if t.Field(i).Tag.Get("json") == id {
			return v.Field(i).String()
		}
	}
	return ""
}

// Over returns l with every non-empty field of o put over it.
func (l Labels) Over(o Labels) Labels {
	dst := reflect.ValueOf(&l).Elem()
	src := reflect.ValueOf(o)
	for i := 0; i < src.NumField(); i++ {
		if s := src.Field(i).String(); strings.TrimSpace(s) != "" {
			dst.Field(i).SetString(s)
		}
	}
	return l
}

// fillLabels gives empty labels their English defaults and caps lengths.
func fillLabels(l *Labels) {
	*l = DefaultLabels().Over(*l)
	capLabels(l)
}

func capLabels(l *Labels) {
	v := reflect.ValueOf(l).Elem()
	for i := 0; i < v.NumField(); i++ {
		if s := v.Field(i).String(); utf8.RuneCountInString(s) > 500 {
			v.Field(i).SetString(string([]rune(s)[:500]))
		}
	}
}
