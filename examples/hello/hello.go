// Package hello is an example Tamamo module that uses every part of the
// module SDK. Read it top to bottom next to the "Writing a module" guide.
//
// What it does:
//
//   - blocks (or challenges) requests to a list of path prefixes (Checker);
//   - counts what Tamamo did with every request (Observer);
//   - marks proxied traffic with headers (RequestModifier, ResponseModifier);
//   - adds a line of text to the checking page (PageExtender + static files);
//   - answers /.tamamo/x/<name>/ping on the protected site (Handler);
//   - has an admin API and a page in the web UI that shows its counters
//     (AdminHandler + UI files);
//   - keeps the counters in its data folder across restarts (Starter, Stopper).
//
// Build a tamamo that contains it, from the repository root:
//
//	go run ./cmd/tamamo-build --tamamo . --with github.com/foxgirlsorg/tamamo/examples/hello=./examples/hello
//
// and switch it on in tamamo.yaml:
//
//	modules:
//	  - name: hello
//	    enabled: true
//	    settings:
//	      blocked_paths: "/wp-admin\n/.env"
//	      message: Checked by our friendly fox.
package hello

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/foxgirlsorg/tamamo/module"
)

// The module's files are compiled into the binary. ui/ holds its web UI
// page, static/ what visitors' browsers may load.
//
//go:embed ui static
var files embed.FS

func sub(dir string) fs.FS {
	f, err := fs.Sub(files, dir)
	if err != nil {
		panic(err)
	}
	return f
}

func init() {
	module.Register(module.Info{
		ID:          "hello",
		Name:        "Hello (example)",
		Description: "Example module: blocks path prefixes, counts verdicts and adds a line to the checking page.",
		Version:     "1.0.0",
		Author:      "Tamamo",
		Homepage:    "https://github.com/foxgirlsorg/tamamo/tree/main/examples/hello",

		// The web UI builds the settings form from this list, and Tamamo
		// checks saved values against it before New runs.
		Settings: []module.Field{
			{
				Name: "blocked_paths", Label: "Blocked paths", Type: module.List,
				Description: "Requests whose path starts with one of these are refused.",
				Placeholder: "/wp-admin",
			},
			{
				Name: "action", Label: "Action", Type: module.Select, Default: module.Block,
				Description: "What happens to a request for a blocked path.",
				Options: []module.Option{
					{Value: module.Block, Label: "Block"},
					{Value: module.Challenge, Label: "Challenge"},
				},
			},
			{
				Name: "message", Label: "Message on the checking page", Type: module.Text,
				Description: "Shown under the card. Leave empty to add nothing.",
			},
			{
				Name: "save_seconds", Label: "Save interval", Type: module.Number, Default: "60", Min: 5, Max: 3600,
				Description: "How often the counters are written to disk, in seconds.",
			},
			{
				Name: "tag_traffic", Label: "Tag proxied traffic", Type: module.Bool, Default: "false",
				Description: "Add an X-Hello header to requests sent to your app and to its responses.",
			},
		},

		Pages:  []module.Page{{ID: "stats", Title: "Hello stats"}}, // Path defaults to index.html
		UI:     sub("ui"),
		Static: sub("static"),

		New: newHello,
	})
}

// hello is one instance of the module: one entry of the modules section.
type hello struct {
	ctx      *module.Context
	prefixes []string
	action   string
	message  string
	tag      bool
	every    time.Duration

	mu      sync.Mutex
	events  map[string]int64 // by module.Event kind
	blocked map[string]int64 // by blocked prefix
	done    chan struct{}
}

// newHello only reads the settings. It also runs when a config is checked
// before saving, so no files, network or goroutines here: those go in Start.
func newHello(ctx *module.Context) (module.Module, error) {
	h := &hello{
		ctx:     ctx,
		action:  ctx.Settings.String("action"),
		message: ctx.Settings.String("message"),
		tag:     ctx.Settings.Bool("tag_traffic"),
		every:   time.Duration(ctx.Settings.Int("save_seconds", 60)) * time.Second,
		events:  map[string]int64{},
		blocked: map[string]int64{},
	}
	for _, p := range ctx.Settings.List("blocked_paths") {
		// An error from New is shown to the admin when they save.
		if !strings.HasPrefix(p, "/") {
			return nil, fmt.Errorf("blocked path %q must start with /", p)
		}
		h.prefixes = append(h.prefixes, p)
	}
	if len(h.message) > 200 {
		return nil, errors.New("the message can be at most 200 characters long")
	}
	return h, nil
}

// ---- Checker: decide about requests before the rules --------------------------

func (h *hello) Check(_ context.Context, r *module.Request) (module.Decision, error) {
	for _, p := range h.prefixes {
		if strings.HasPrefix(r.Path, p) {
			h.mu.Lock()
			h.blocked[p]++
			h.mu.Unlock()
			return module.Decision{Action: h.action, Reason: "path " + p}, nil
		}
	}
	// No opinion: the next module, then the rules, decide.
	return module.Decision{}, nil
}

// ---- Observer: see every verdict ----------------------------------------------

func (h *hello) Observe(e module.Event) {
	h.mu.Lock()
	h.events[e.Kind]++
	h.mu.Unlock()
}

// ---- RequestModifier / ResponseModifier: edit proxied traffic -----------------

func (h *hello) ModifyRequest(out *http.Request, r *module.Request) {
	if h.tag {
		out.Header.Set("X-Hello", "checked-by-tamamo")
	}
}

func (h *hello) ModifyResponse(resp *http.Response, r *module.Request) error {
	if h.tag {
		resp.Header.Set("X-Hello", h.ctx.Name)
	}
	return nil
}

// ---- PageExtender: add to the checking page ------------------------------------

func (h *hello) ExtendPage(p *module.PageRequest) module.PageParts {
	if h.message == "" {
		return module.PageParts{}
	}
	return module.PageParts{
		// Escape whatever comes from settings: the snippet is inserted as HTML.
		Body:   `<p class="hello-banner">` + html.EscapeString(h.message) + `</p>`,
		Styles: []string{p.AssetURL("banner.css")}, // static/banner.css
	}
}

// ---- Handler: public URLs under /.tamamo/x/<name>/ -----------------------------

// ServeHTTP answers requests from the internet, unchecked by Tamamo. The
// path is what follows the module's prefix: /.tamamo/x/hello/ping -> /ping.
func (h *hello) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/ping" || r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(`{"pong":true}`))
}

// ---- AdminHandler: the module's admin API under /api/x/<name>/ -----------------

type blockedPath struct {
	Path  string `json:"path"`
	Count int64  `json:"count"`
}

type snapshot struct {
	Events  map[string]int64 `json:"events"`
	Blocked []blockedPath    `json:"blocked"`
}

func (h *hello) snapshot() snapshot {
	h.mu.Lock()
	defer h.mu.Unlock()
	s := snapshot{Events: map[string]int64{}, Blocked: []blockedPath{}}
	for k, v := range h.events {
		s.Events[k] = v
	}
	for p, n := range h.blocked {
		s.Blocked = append(s.Blocked, blockedPath{Path: p, Count: n})
	}
	sort.Slice(s.Blocked, func(i, j int) bool { return s.Blocked[i].Count > s.Blocked[j].Count })
	return s
}

// ServeAdmin is only reached by a signed-in admin. Tamamo has already
// checked the CSRF header for POST.
func (h *hello) ServeAdmin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.URL.Path == "/stats" && r.Method == http.MethodGet:
		_ = json.NewEncoder(w).Encode(h.snapshot())
	case r.URL.Path == "/reset" && r.Method == http.MethodPost:
		h.mu.Lock()
		clear(h.events)
		clear(h.blocked)
		h.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
	default:
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "not found"})
	}
}

// ---- Starter / Stopper: background work and the data folder --------------------

func (h *hello) file() (string, error) {
	dir, err := h.ctx.DataDir() // <data>/modules/<name>, created on first use
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "counters.json"), nil
}

// Start loads the saved counters and starts the loop that saves them. It
// must return promptly; ctx is cancelled when the module is switched off,
// its settings change or Tamamo stops.
func (h *hello) Start(ctx context.Context) error {
	path, err := h.file()
	if err != nil {
		return err
	}
	if b, err := os.ReadFile(path); err == nil {
		var s snapshot
		if json.Unmarshal(b, &s) == nil {
			h.mu.Lock()
			for k, v := range s.Events {
				h.events[k] = v
			}
			for _, p := range s.Blocked {
				h.blocked[p.Path] = p.Count
			}
			h.mu.Unlock()
		}
	}
	h.done = make(chan struct{})
	go func() {
		defer close(h.done)
		t := time.NewTicker(h.every)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := h.save(); err != nil {
					h.ctx.Logger.Warn("could not save counters", "err", err)
				}
			}
		}
	}()
	h.ctx.Logger.Info("hello is counting", "blocked_paths", len(h.prefixes))
	return nil
}

// Stop runs after the Start context is cancelled.
func (h *hello) Stop() error {
	if h.done != nil {
		<-h.done
	}
	return h.save()
}

func (h *hello) save() error {
	path, err := h.file()
	if err != nil {
		return err
	}
	b, err := json.Marshal(h.snapshot())
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
