package hello

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/foxgirlsorg/tamamo/module"
)

// A module is tested like any Go code: look it up, create it with settings
// and call its hooks.
func create(t *testing.T, settings module.Settings) *hello {
	t.Helper()
	info, ok := module.Lookup("hello")
	if !ok {
		t.Fatal("hello is not registered")
	}
	dir := module.InstanceDir(t.TempDir(), "hello")
	m, err := info.Create(module.NewContext("hello", settings, nil, dir))
	if err != nil {
		t.Fatal(err)
	}
	return m.(*hello)
}

func TestCheck(t *testing.T) {
	h := create(t, module.Settings{"blocked_paths": "/wp-admin\n/.env", "action": "challenge"})
	d, err := h.Check(context.Background(), &module.Request{Path: "/wp-admin/install.php"})
	if err != nil || d.Action != module.Challenge {
		t.Errorf("blocked path: %+v %v", d, err)
	}
	if d, _ := h.Check(context.Background(), &module.Request{Path: "/blog"}); d.Action != module.NoOpinion {
		t.Errorf("other paths are none of its business: %+v", d)
	}
}

func TestBadSettings(t *testing.T) {
	info, _ := module.Lookup("hello")
	for _, s := range []module.Settings{
		{"blocked_paths": "wp-admin"},
		{"action": "allow"},
		{"save_seconds": "1"},
	} {
		if _, err := info.Create(module.NewContext("hello", s, nil, "")); err == nil {
			t.Errorf("accepted %v", s)
		}
	}
}

func TestPageAndAdminAPI(t *testing.T) {
	h := create(t, module.Settings{"message": "<b>hi</b>"})
	parts := h.ExtendPage(&module.PageRequest{AssetBase: "/.tamamo/modules/hello"})
	if !strings.Contains(parts.Body, "&lt;b&gt;hi") || parts.Styles[0] != "/.tamamo/modules/hello/banner.css" {
		t.Errorf("page parts: %+v", parts)
	}

	h.Observe(module.Event{Kind: module.EventBlock})
	w := httptest.NewRecorder()
	h.ServeAdmin(w, httptest.NewRequest(http.MethodGet, "/stats", nil))
	if !strings.Contains(w.Body.String(), `"block":1`) {
		t.Errorf("stats: %s", w.Body.String())
	}
}

func TestCountersSurviveRestart(t *testing.T) {
	dir := module.InstanceDir(t.TempDir(), "hello")
	info, _ := module.Lookup("hello")
	run := func() *hello {
		m, err := info.Create(module.NewContext("hello", nil, nil, dir))
		if err != nil {
			t.Fatal(err)
		}
		return m.(*hello)
	}
	first := run()
	ctx, cancel := context.WithCancel(context.Background())
	if err := first.Start(ctx); err != nil {
		t.Fatal(err)
	}
	first.Observe(module.Event{Kind: module.EventSolve})
	cancel()
	if err := first.Stop(); err != nil {
		t.Fatal(err)
	}

	second := run()
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	if err := second.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if n := second.snapshot().Events[module.EventSolve]; n != 1 {
		t.Errorf("solve count after a restart: %d", n)
	}
}
