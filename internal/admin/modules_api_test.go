package admin

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tamamo/tamamo/internal/config"
)

func TestModulesAPIAndPreview(t *testing.T) {
	e := newEnv(t)
	c := e.setup()
	h := e.h.(*handler)
	dir := h.modulesDir()
	if err := os.MkdirAll(filepath.Join(dir, "banner"), 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(dir, "banner", "body.html"), []byte(`<p class="hello">hi`), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "banner", "style.css"), []byte(`.hello{}`), 0o644)

	r := e.do("GET", "/api/modules", "", c, false)
	if r.code != 200 || r.body["data_dir"] != dir {
		t.Fatalf("modules: %d %s", r.code, r.raw)
	}
	if !strings.Contains(r.raw, `"name":"ratelimit"`) || !strings.Contains(r.raw, `"name":"bypass-header"`) ||
		!strings.Contains(r.raw, `{"name":"banner","files":["body.html","style.css"]}`) {
		t.Errorf("modules body %s", r.raw)
	}
	if r := e.do("GET", "/api/modules", "", nil, false); r.code != 401 {
		t.Errorf("unauthenticated: %d", r.code)
	}

	if err := e.cfg.Update(func(c *config.Config) error {
		c.Modules = []config.ModuleConfig{{Name: "banner", Type: "page", Enabled: true}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	r = e.do("POST", "/api/preview", `{"state":"checking","lang":"uk"}`, c, true)
	if r.code != 200 || !strings.Contains(r.raw, `<html lang="uk">`) ||
		!strings.Contains(r.raw, config.DefaultTranslations()["uk"].Texts.Checking.Heading) {
		t.Errorf("uk preview: %d", r.code)
	}
	if !strings.Contains(r.raw, `<p class="hello">hi</p>`) || !strings.Contains(r.raw, `href="/assets/modules/banner/style.css?v=`) {
		t.Error("page module missing from the preview")
	}
	if r := e.do("GET", "/assets/modules/banner/style.css", "", c, false); r.code != 200 || r.raw != ".hello{}" {
		t.Errorf("preview module asset: %d %q", r.code, r.raw)
	}
	for _, p := range []string{"/assets/modules/banner/body.html", "/assets/modules/banner/../../config.json", "/assets/modules/nope/style.css"} {
		if r := e.do("GET", p, "", c, false); r.code == 200 {
			t.Errorf("%s served", p)
		}
	}
	if r := e.do("GET", "/assets/modules/banner/style.css", "", nil, false); r.code != 404 {
		t.Errorf("module asset without a session: %d", r.code)
	}
	if r := e.do("POST", "/api/preview", `{"lang":"en"}`, c, true); r.code != 200 || !strings.Contains(r.raw, `<html lang="en">`) {
		t.Errorf("main language preview: %d", r.code)
	}
	if r := e.do("POST", "/api/preview", `{"lang":"xx"}`, c, true); r.code != 400 {
		t.Errorf("unknown language: %d", r.code)
	}
}
