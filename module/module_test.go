package module

import (
	"errors"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

func mustPanic(t *testing.T, want string, fn func()) {
	t.Helper()
	defer func() {
		p := recover()
		if p == nil || !strings.Contains(p.(string), want) {
			t.Errorf("got panic %v, want one containing %q", p, want)
		}
	}()
	fn()
}

func newNothing(*Context) (Module, error) { return struct{}{}, nil }

func TestRegister(t *testing.T) {
	Register(Info{
		ID: "reg-test", New: newNothing,
		Settings: []Field{{Name: "a"}, {Name: "b", Type: Select, Options: []Option{{Value: "x"}}}},
		Pages:    []Page{{ID: "main"}},
		UI:       fstest.MapFS{"index.html": {Data: []byte("x")}},
	})
	info, ok := Lookup("reg-test")
	if !ok {
		t.Fatal("not registered")
	}
	if info.Name != "reg-test" || info.Settings[0].Type != Text || info.Settings[0].Label != "a" ||
		info.Settings[1].Options[0].Label != "x" || info.Pages[0].Path != "index.html" || info.Pages[0].Title != "main" {
		t.Errorf("defaults not filled in: %+v", info)
	}
	found := false
	for _, i := range Registered() {
		found = found || i.ID == "reg-test"
	}
	if !found {
		t.Error("Registered does not list it")
	}
	mustPanic(t, "registered twice", func() { Register(Info{ID: "reg-test", New: newNothing}) })
	mustPanic(t, "must be a-z", func() { Register(Info{ID: "Bad ID", New: newNothing}) })
	mustPanic(t, "no New", func() { Register(Info{ID: "no-new"}) })
	mustPanic(t, "unknown type", func() { Register(Info{ID: "t1", New: newNothing, Settings: []Field{{Name: "a", Type: "color"}}}) })
	mustPanic(t, "no options", func() { Register(Info{ID: "t2", New: newNothing, Settings: []Field{{Name: "a", Type: Select}}}) })
	mustPanic(t, "name of its own", func() { Register(Info{ID: "t3", New: newNothing, Settings: []Field{{Name: "a"}, {Name: "a"}}}) })
	mustPanic(t, "default", func() {
		Register(Info{ID: "t4", New: newNothing, Settings: []Field{{Name: "n", Type: Number, Default: "x"}}})
	})
	mustPanic(t, "no UI files", func() { Register(Info{ID: "t5", New: newNothing, Pages: []Page{{ID: "p"}}}) })
}

func TestPrepareAndCreate(t *testing.T) {
	info := Info{
		ID: "prep",
		Settings: []Field{
			{Name: "token", Required: true},
			{Name: "limit", Type: Number, Default: "10", Min: 1, Max: 100},
			{Name: "on", Type: Bool, Default: "true"},
			{Name: "mode", Type: Select, Default: "a", Options: []Option{{Value: "a"}, {Value: "b"}}},
		},
		New: func(ctx *Context) (Module, error) {
			switch ctx.Settings.String("token") {
			case "panic":
				panic("oops")
			case "nil":
				return nil, nil
			case "err":
				return nil, errors.New("nope")
			}
			return ctx, nil
		},
	}
	if err := checkInfo(&info); err != nil {
		t.Fatal(err)
	}
	s, err := info.Prepare(map[string]string{"token": "t", "extra": "kept"})
	if err != nil {
		t.Fatal(err)
	}
	if s["limit"] != "10" || s["on"] != "true" || s["mode"] != "a" || s["extra"] != "kept" {
		t.Errorf("defaults: %v", s)
	}
	for name, in := range map[string]map[string]string{
		"required":  {},
		"range":     {"token": "t", "limit": "0"},
		"number":    {"token": "t", "limit": "1.5"},
		"bool":      {"token": "t", "on": "maybe"},
		"selection": {"token": "t", "mode": "c"},
	} {
		if _, err := info.Prepare(in); err == nil {
			t.Errorf("%s: accepted %v", name, in)
		}
	}
	m, err := info.Create(NewContext("inst", Settings{"token": "t"}, nil, ""))
	if err != nil {
		t.Fatal(err)
	}
	ctx := m.(*Context)
	if ctx.Name != "inst" || ctx.Settings.Int("limit", 0) != 10 || ctx.Logger == nil {
		t.Errorf("context: %+v", ctx)
	}
	if _, err := ctx.DataDir(); err == nil {
		t.Error("DataDir without a folder should fail")
	}
	for _, tok := range []string{"panic", "nil", "err"} {
		if _, err := info.Create(NewContext("inst", Settings{"token": tok}, nil, "")); err == nil {
			t.Errorf("token %q: no error", tok)
		}
	}
	dir := InstanceDir(t.TempDir(), "inst")
	got, err := NewContext("inst", nil, nil, dir).DataDir()
	if err != nil || got != dir {
		t.Errorf("DataDir: %q %v", got, err)
	}
}

func TestSettings(t *testing.T) {
	s := Settings{"n": " 42 ", "b": "Yes", "d1": "90", "d2": "5m", "list": "a, b\n\n c\r\nd", "bad": "x"}
	if s.String("n") != "42" || s.Int("n", 0) != 42 || s.Int("bad", 7) != 7 || s.Int("missing", 7) != 7 {
		t.Error("String/Int")
	}
	if !s.Bool("b") || s.Bool("bad") || s.Bool("missing") {
		t.Error("Bool")
	}
	if s.Duration("d1", 0) != 90*time.Second || s.Duration("d2", 0) != 5*time.Minute || s.Duration("bad", time.Hour) != time.Hour {
		t.Error("Duration")
	}
	if got := strings.Join(s.List("list"), "|"); got != "a|b|c|d" {
		t.Errorf("List: %q", got)
	}
	if len(s.List("missing")) != 0 {
		t.Error("List of a missing key")
	}
	p := PageRequest{AssetBase: "/.tamamo/modules/x"}
	if p.AssetURL("/a.css") != "/.tamamo/modules/x/a.css" {
		t.Errorf("AssetURL: %q", p.AssetURL("/a.css"))
	}
}
