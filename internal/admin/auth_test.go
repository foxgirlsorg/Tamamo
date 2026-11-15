package admin

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/foxgirlsorg/tamamo/internal/assets"
	"github.com/foxgirlsorg/tamamo/internal/config"
)

func fxAdmin(t *testing.T) http.Handler {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("TAMAMO_TARGET", "")
	cfg, err := config.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	st, err := assets.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	return New(Options{Config: cfg, Assets: st, Version: "test"})
}

func fxAdminDo(h http.Handler, method, path, body string, cookie *http.Cookie, remote string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.RemoteAddr = remote
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	if method != http.MethodGet {
		r.Header.Set(csrfHeader, "1")
	}
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestAdminAuthFailsClosed(t *testing.T) {
	h := fxAdmin(t)
	// Before setup nothing protected is reachable.
	for _, p := range []string{"/api/config", "/api/stats"} {
		if w := fxAdminDo(h, http.MethodGet, p, "", nil, "192.0.2.1:1"); w.Code != http.StatusUnauthorized {
			t.Errorf("GET %s before setup: %d", p, w.Code)
		}
	}
	setup := fxAdminDo(h, http.MethodPost, "/api/setup", `{"username":"admin","password":"correct horse battery"}`, nil, "192.0.2.1:1")
	if setup.Code != http.StatusOK {
		t.Fatalf("setup: %d %s", setup.Code, setup.Body)
	}
	for name, body := range map[string]string{
		"wrong username":   `{"username":"nobody","password":"correct horse battery"}`,
		"wrong password":   `{"username":"admin","password":"hunter2hunter2"}`,
		"missing password": `{"username":"admin"}`,
		"missing username": `{"password":"correct horse battery"}`,
		"empty":            `{}`,
	} {
		w := fxAdminDo(h, http.MethodPost, "/api/login", body, nil, "198.51.100.1:1")
		if w.Code != http.StatusUnauthorized {
			t.Errorf("%s: %d", name, w.Code)
		}
		for _, c := range w.Result().Cookies() {
			if c.Value != "" && c.MaxAge >= 0 {
				t.Errorf("%s: session cookie set", name)
			}
		}
	}
	forged := &http.Cookie{Name: sessionCookie, Value: "forged-session-token"}
	for _, p := range []string{"/api/config", "/api/stats"} {
		if w := fxAdminDo(h, http.MethodGet, p, "", forged, "192.0.2.1:1"); w.Code != http.StatusUnauthorized {
			t.Errorf("GET %s with forged session: %d", p, w.Code)
		}
		if w := fxAdminDo(h, http.MethodGet, p, "", nil, "192.0.2.1:1"); w.Code != http.StatusUnauthorized || w.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("GET %s without session: %d cache=%q", p, w.Code, w.Header().Get("Cache-Control"))
		}
	}
	// Valid credentials work.
	if w := fxAdminDo(h, http.MethodPost, "/api/login", `{"username":"admin","password":"correct horse battery"}`, nil, "203.0.113.1:1"); w.Code != http.StatusOK {
		t.Errorf("valid login: %d", w.Code)
	}
}
