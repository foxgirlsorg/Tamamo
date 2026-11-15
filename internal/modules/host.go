// Package modules runs the Go modules compiled into this build (see the
// public module package for the SDK): it creates an instance for every
// enabled entry of the config's modules section, starts and stops their
// background work and hands the instances to the server and the admin API.
package modules

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"log/slog"
	"mime"
	"net/http"
	"path"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/foxgirlsorg/tamamo/internal/config"
	"github.com/foxgirlsorg/tamamo/module"
)

// Instance is one running module: an enabled entry of the modules section.
type Instance struct {
	Cfg  config.ModuleConfig
	Info module.Info
	Mod  module.Module

	// The hooks the module implements (nil when it doesn't).
	Checker  module.Checker
	Observer module.Observer
	ReqMod   module.RequestModifier
	RespMod  module.ResponseModifier
	Page     module.PageExtender
	Public   module.Handler
	Admin    module.AdminHandler

	cancel   context.CancelFunc
	startErr string
}

// StartError is what Start returned, or "" (also for modules without Start).
func (in *Instance) StartError() string { return in.startErr }

// Hooks lists the hook interfaces the module implements, for display.
func (in *Instance) Hooks() []string { return HooksOf(in.Mod) }

// HooksOf lists the hook interfaces a module value implements.
func HooksOf(m module.Module) []string {
	out := []string{}
	add := func(ok bool, name string) {
		if ok {
			out = append(out, name)
		}
	}
	_, ok := m.(module.Checker)
	add(ok, "check")
	_, ok = m.(module.Observer)
	add(ok, "observe")
	_, ok = m.(module.RequestModifier)
	add(ok, "request")
	_, ok = m.(module.ResponseModifier)
	add(ok, "response")
	_, ok = m.(module.PageExtender)
	add(ok, "page")
	_, ok = m.(module.Handler)
	add(ok, "http")
	_, ok = m.(module.AdminHandler)
	add(ok, "admin")
	_, ok = m.(module.Starter)
	add(ok, "background")
	return out
}

// Host owns the module instances of the current config.
type Host struct {
	dataDir string

	mu      sync.Mutex
	applied *config.Config
	cache   map[string]*Instance // by the entry's JSON
	current atomic.Pointer[[]*Instance]
	closed  bool
}

// NewHost creates a host. Instances keep their files under
// <dataDir>/modules/<name>; dataDir may be "" (no folder available).
func NewHost(dataDir string) *Host {
	h := &Host{dataDir: dataDir, cache: map[string]*Instance{}}
	h.current.Store(&[]*Instance{})
	return h
}

// Apply makes the running instances match cfg's modules section. Entries
// that didn't change keep their instance (and whatever it holds in memory);
// removed or changed ones are stopped, new ones created and started.
func (h *Host) Apply(cfg *config.Config) []*Instance {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed || h.applied == cfg {
		return *h.current.Load()
	}
	next := map[string]*Instance{}
	list := []*Instance{}
	for _, m := range cfg.Modules {
		if !m.Enabled {
			continue
		}
		kb, _ := json.Marshal(m)
		key := string(kb)
		in := h.cache[key]
		if in == nil {
			var err error
			if in, err = h.create(m); err != nil {
				slog.Error("module could not be started; it is skipped", "module", m.Name, "err", err)
				continue
			}
		}
		next[key] = in
		list = append(list, in)
	}
	for key, in := range h.cache {
		if next[key] == nil {
			stop(in)
		}
	}
	h.cache = next
	h.applied = cfg
	h.current.Store(&list)
	return list
}

func (h *Host) create(m config.ModuleConfig) (*Instance, error) {
	info, ok := module.Lookup(m.ModuleID())
	if !ok {
		return nil, fmt.Errorf("no module with the ID %q is compiled into this build", m.ModuleID())
	}
	ctx := module.NewContext(m.Name, m.Settings, append([]string{}, m.Sites...), module.InstanceDir(h.dataDir, m.Name))
	mod, err := info.Create(ctx)
	if err != nil {
		return nil, err
	}
	in := &Instance{Cfg: m, Info: info, Mod: mod}
	in.Checker, _ = mod.(module.Checker)
	in.Observer, _ = mod.(module.Observer)
	in.ReqMod, _ = mod.(module.RequestModifier)
	in.RespMod, _ = mod.(module.ResponseModifier)
	in.Page, _ = mod.(module.PageExtender)
	in.Public, _ = mod.(module.Handler)
	in.Admin, _ = mod.(module.AdminHandler)

	runCtx, cancel := context.WithCancel(context.Background())
	in.cancel = cancel
	if st, ok := mod.(module.Starter); ok {
		if err := safely(func() error { return st.Start(runCtx) }); err != nil {
			// The module stays loaded so its settings and pages remain
			// reachable; the web UI shows the error.
			in.startErr = err.Error()
			slog.Error("module failed to start", "module", m.Name, "err", err)
		}
	}
	slog.Info("module started", "module", m.Name, "id", info.ID, "hooks", strings.Join(in.Hooks(), ","))
	return in, nil
}

func stop(in *Instance) {
	in.cancel()
	if st, ok := in.Mod.(module.Stopper); ok {
		if err := safely(st.Stop); err != nil {
			slog.Warn("module did not stop cleanly", "module", in.Cfg.Name, "err", err)
		}
	}
	slog.Info("module stopped", "module", in.Cfg.Name)
}

// safely runs fn, turning a panic into an error.
func safely(fn func() error) (err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("panic: %v", p)
		}
	}()
	return fn()
}

// Instances returns the running instances, in config order. Treat the slice
// as read-only.
func (h *Host) Instances() []*Instance { return *h.current.Load() }

// Instance returns the running instance called name, or nil.
func (h *Host) Instance(name string) *Instance {
	for _, in := range h.Instances() {
		if in.Cfg.Name == name {
			return in
		}
	}
	return nil
}

// Close stops every instance. The host can't be used afterwards.
func (h *Host) Close() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return
	}
	h.closed = true
	for _, in := range h.cache {
		stop(in)
	}
	h.cache = map[string]*Instance{}
	h.current.Store(&[]*Instance{})
}

// ---- hooks ------------------------------------------------------------------

// Check asks in's Checker about a request, turning a panic into an error.
func Check(ctx context.Context, in *Instance, r *module.Request) (d module.Decision, err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("panic: %v", p)
		}
	}()
	return in.Checker.Check(ctx, r)
}

// Observe tells every observer switched on for the event's site about it.
func Observe(list []*Instance, e module.Event) {
	for _, in := range list {
		if in.Observer == nil || !in.Cfg.AppliesTo(e.Site) {
			continue
		}
		func() {
			defer func() {
				if p := recover(); p != nil && throttle("observe:"+in.Cfg.Name) {
					slog.Warn("module panicked in Observe", "module", in.Cfg.Name, "panic", p)
				}
			}()
			in.Observer.Observe(e)
		}()
	}
}

// PageParts collects what the modules switched on for the request's site add
// to a Tamamo page. assetBase is where modules' static files are served
// (e.g. "/.tamamo/modules"); each module gets assetBase + "/" + its ID.
func PageParts(list []*Instance, req module.PageRequest, assetBase string) []NamedParts {
	var out []NamedParts
	base := strings.TrimRight(assetBase, "/")
	for _, in := range list {
		if in.Page == nil || !in.Cfg.AppliesTo(req.Site) {
			continue
		}
		pr := req
		pr.AssetBase = base + "/" + in.Info.ID
		var parts module.PageParts
		func() {
			defer func() {
				if p := recover(); p != nil && throttle("page:"+in.Cfg.Name) {
					slog.Warn("module panicked in ExtendPage", "module", in.Cfg.Name, "panic", p)
				}
			}()
			parts = in.Page.ExtendPage(&pr)
		}()
		out = append(out, NamedParts{Name: in.Cfg.Name, PageParts: parts})
	}
	return out
}

// NamedParts is one module's additions to a page.
type NamedParts struct {
	Name string
	module.PageParts
}

var (
	warnMu   sync.Mutex
	warnedAt = map[string]time.Time{}
)

// throttle reports whether a warning with this key may be logged now (at
// most once a minute, so a broken module can't flood the log).
func throttle(key string) bool {
	warnMu.Lock()
	defer warnMu.Unlock()
	now := time.Now()
	if t, ok := warnedAt[key]; ok && now.Sub(t) < time.Minute {
		return false
	}
	if len(warnedAt) > 1000 {
		clear(warnedAt)
	}
	warnedAt[key] = now
	return true
}

// ServeStripped calls a module's handler with the request's path replaced by
// path (the part after the module's own prefix). A panic becomes a 500.
func ServeStripped(w http.ResponseWriter, r *http.Request, path, name string, serve func(http.ResponseWriter, *http.Request)) {
	r2 := r.Clone(r.Context())
	u := *r.URL
	u.Path, u.RawPath = path, ""
	r2.URL = &u
	defer func() {
		if p := recover(); p != nil {
			if p == http.ErrAbortHandler {
				panic(p)
			}
			slog.Error("module panicked while serving a request", "module", name, "path", path, "panic", p)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}
	}()
	serve(w, r2)
}

// ---- files ------------------------------------------------------------------

var fileTypes = map[string]string{
	".js":    "text/javascript; charset=utf-8",
	".mjs":   "text/javascript; charset=utf-8",
	".css":   "text/css; charset=utf-8",
	".html":  "text/html; charset=utf-8",
	".htm":   "text/html; charset=utf-8",
	".json":  "application/json",
	".map":   "application/json",
	".wasm":  "application/wasm",
	".svg":   "image/svg+xml",
	".png":   "image/png",
	".jpg":   "image/jpeg",
	".jpeg":  "image/jpeg",
	".gif":   "image/gif",
	".webp":  "image/webp",
	".avif":  "image/avif",
	".ico":   "image/x-icon",
	".woff":  "font/woff",
	".woff2": "font/woff2",
	".ttf":   "font/ttf",
	".otf":   "font/otf",
	".txt":   "text/plain; charset=utf-8",
	".mp4":   "video/mp4",
	".webm":  "video/webm",
	".mp3":   "audio/mpeg",
	".ogg":   "audio/ogg",
}

// ContentType returns the MIME type served for a file name.
func ContentType(name string) string {
	ext := strings.ToLower(path.Ext(name))
	if ct := fileTypes[ext]; ct != "" {
		return ct
	}
	if ct := mime.TypeByExtension(ext); ct != "" {
		return ct
	}
	return "application/octet-stream"
}

// SafeFile reports whether file is a plain relative path without dotfiles.
func SafeFile(file string) bool {
	if file == "" || len(file) > 512 || !fs.ValidPath(file) || strings.ContainsAny(file, "\\:\x00") {
		return false
	}
	for _, seg := range strings.Split(file, "/") {
		if seg == "" || strings.HasPrefix(seg, ".") {
			return false
		}
	}
	return true
}

// ServeFS serves file from one of a module's file systems (Info.Static or
// Info.UI). Anything that isn't a regular file answers 404. document says
// whether HTML may be shown as a page (the module's web UI pages) or must be
// locked down (files visitors can reach).
func ServeFS(w http.ResponseWriter, r *http.Request, fsys fs.FS, file string, document bool) {
	if fsys == nil || !SafeFile(file) {
		http.NotFound(w, r)
		return
	}
	fi, err := fs.Stat(fsys, file)
	if err != nil || !fi.Mode().IsRegular() {
		http.NotFound(w, r)
		return
	}
	b, err := fs.ReadFile(fsys, file)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	h := w.Header()
	h.Set("Content-Type", ContentType(file))
	h.Set("X-Content-Type-Options", "nosniff")
	if !document {
		switch strings.ToLower(path.Ext(file)) {
		case ".svg", ".html", ".htm", ".xml":
			// Opened directly, these would be documents on the protected origin.
			h.Set("Content-Security-Policy", "sandbox; default-src 'none'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; font-src 'self' data:")
		}
	}
	if h.Get("Cache-Control") == "" {
		if r.URL.Query().Get("v") != "" {
			h.Set("Cache-Control", "public, max-age=86400")
		} else {
			h.Set("Cache-Control", "public, max-age=300")
		}
	}
	http.ServeContent(w, r, path.Base(file), time.Time{}, bytes.NewReader(b))
}
