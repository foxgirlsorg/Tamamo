// Package module is the SDK for Tamamo modules.
//
// A Tamamo module is an ordinary Go module (its own repository and go.mod)
// that imports this package, registers itself from an init function and is
// compiled into the tamamo binary. Nothing is loaded at run time.
//
// The smallest module:
//
//	package hello
//
//	import (
//		"context"
//		"strings"
//
//		"github.com/foxgirlsorg/tamamo/module"
//	)
//
//	func init() {
//		module.Register(module.Info{
//			ID:          "block-wp-admin",
//			Name:        "Block /wp-admin",
//			Description: "Refuses WordPress probes on sites that aren't WordPress.",
//			New: func(ctx *module.Context) (module.Module, error) {
//				return blocker{}, nil
//			},
//		})
//	}
//
//	type blocker struct{}
//
//	func (blocker) Check(_ context.Context, r *module.Request) (module.Decision, error) {
//		if strings.HasPrefix(r.Path, "/wp-admin") {
//			return module.Decision{Action: module.Block, Reason: "not WordPress"}, nil
//		}
//		return module.Decision{}, nil
//	}
//
// Build a tamamo that contains it with
//
//	tamamo-build --with github.com/you/tamamo-hello
//
// and switch it on in tamamo.yaml or in the web UI (Modules).
//
// # What a module can do
//
// The value returned by Info.New implements any combination of the hook
// interfaces in this package. Tamamo checks which ones it implements:
//
//   - Checker decides about requests before the rules do.
//   - Observer sees every verdict (allowed, challenged, blocked, solved...).
//   - RequestModifier and ResponseModifier edit proxied traffic.
//   - PageExtender adds HTML, styles and scripts to the checking page.
//   - Handler serves the module's own public URLs under /.tamamo/x/<name>/.
//   - AdminHandler serves the module's own admin API under /api/x/<name>/.
//   - Starter and Stopper run background work.
//
// Info.Settings describes the module's settings; the web UI builds the form
// from it. Info.Pages and Info.UI give the module its own pages in the web
// UI, and Info.Static ships files (images, CSS, JS) with the binary.
package module

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Actions a Decision can take. The empty action means "no opinion": the next
// module (and then the rules) decide.
const (
	NoOpinion = ""
	Allow     = "allow"
	Challenge = "challenge"
	Block     = "block"
)

// ValidAction reports whether a is an action a Decision may carry.
func ValidAction(a string) bool {
	switch a {
	case NoOpinion, Allow, Challenge, Block:
		return true
	}
	return false
}

// Request is what a module sees of one visitor request. Header is the live
// request header: treat it as read-only.
type Request struct {
	Site      string // site ID ("default" for the default site)
	Method    string
	Host      string // lower-case, without port
	Path      string // normalized path
	Query     string // raw query, without "?"
	UserAgent string
	IP        netip.Addr // client address (may be invalid if unknown)
	Header    http.Header
}

// Decision is a Checker's answer.
type Decision struct {
	// Action is "" (no opinion), "allow", "challenge" or "block".
	Action string `json:"action"`
	// Difficulty is the proof-of-work difficulty for "challenge" (1-8);
	// 0 means the site's default.
	Difficulty int `json:"difficulty"`
	// Reason is a short explanation for logs.
	Reason string `json:"reason"`
}

// Module is the value Info.New returns. It carries no methods of its own:
// implement the hook interfaces below that the module needs.
type Module any

// Checker looks at a request before the rules and decides about it. The
// first module with an opinion wins. Check is called concurrently.
type Checker interface {
	Check(ctx context.Context, r *Request) (Decision, error)
}

// Kinds of Event.
const (
	EventPass      = "pass"      // a valid pass cookie let the request through
	EventAllow     = "allow"     // a rule, a module or the default let it through
	EventChallenge = "challenge" // the checking page was served
	EventBlock     = "block"     // the request was refused
	EventSolve     = "solve"     // a proof of work was accepted
	EventFail      = "fail"      // a proof of work was rejected
)

// Event is one thing Tamamo did with a request.
type Event struct {
	Time      time.Time
	Kind      string // one of the Event* constants
	Site      string
	Host      string
	Path      string
	UserAgent string
	IP        string // "" if unknown
	// Rule names what decided: a rule's name, "module:<name>",
	// "webhook:<name>", "ratelimit", "bypass:<name>" or "" for the default.
	Rule string
}

// Observer is told about every Event of the sites the module is switched on
// for. Observe runs on the request path: return quickly and hand slow work
// to a goroutine started in Start.
type Observer interface {
	Observe(e Event)
}

// RequestModifier edits requests on their way to the protected app, after
// Tamamo let them through. out is the outgoing request; r describes the
// visitor's request. Not called behind nginx auth_request, where Tamamo
// doesn't proxy.
type RequestModifier interface {
	ModifyRequest(out *http.Request, r *Request)
}

// ResponseModifier edits the app's responses before they reach the visitor.
// Returning an error makes Tamamo answer 502. Not called behind nginx
// auth_request.
type ResponseModifier interface {
	ModifyResponse(resp *http.Response, r *Request) error
}

// PageRequest describes the Tamamo page being rendered.
type PageRequest struct {
	Site    string // site ID
	Host    string
	State   string // checking, success, denied or error
	Lang    string // language shown, "" for the page's main language
	Preview bool   // true in the web UI's page designer
	// AssetBase is where the module's Info.Static files are served for this
	// page, without a trailing slash.
	AssetBase string
}

// AssetURL returns the URL of a file from Info.Static.
func (p *PageRequest) AssetURL(name string) string {
	return p.AssetBase + "/" + strings.TrimLeft(name, "/")
}

// PageParts is what a module adds to a Tamamo page.
type PageParts struct {
	Head    string   // HTML inserted at the end of <head>
	Body    string   // HTML inserted at the end of <body>, above the credit line
	Styles  []string // stylesheet URLs
	Scripts []string // script URLs, loaded with defer
}

// PageExtender adds to the checking, success, denied and error pages.
// Elements a snippet leaves open are closed for it. The "Protected by
// Tamamo" line cannot be removed.
type PageExtender interface {
	ExtendPage(p *PageRequest) PageParts
}

// Handler serves the module's own public URLs. Requests to
// /.tamamo/x/<name>/<rest> on a site the module is switched on for arrive
// with r.URL.Path set to "/<rest>". They come straight from the internet,
// unchecked: validate everything and limit body sizes.
type Handler interface {
	http.Handler
}

// AdminHandler serves the module's own admin API. Requests to
// /api/x/<name>/<rest> arrive with r.URL.Path set to "/<rest>", only from a
// signed-in admin and, for anything but GET and HEAD, only with the
// X-Tamamo-Request header (CSRF protection).
type AdminHandler interface {
	ServeAdmin(w http.ResponseWriter, r *http.Request)
}

// Starter runs background work. Start is called once after New when the
// module is switched on; ctx is cancelled when it is switched off, its
// settings change or Tamamo stops. Start must return promptly: put loops in
// a goroutine.
type Starter interface {
	Start(ctx context.Context) error
}

// Stopper is called after the Start context is cancelled, to flush and
// release what the module holds.
type Stopper interface {
	Stop() error
}

// ---- settings ---------------------------------------------------------------

// Field types. The web UI picks the input from the type.
const (
	Text     = "text"     // one line (the default)
	Secret   = "secret"   // one line, hidden like a password
	Number   = "number"   // whole number, optionally within Min..Max
	Bool     = "bool"     // switch; the value is "true" or "false"
	Select   = "select"   // one of Options
	TextArea = "textarea" // several lines
	List     = "list"     // several values, stored one per line
)

// Option is one choice of a Select field.
type Option struct {
	Value string `json:"value"`
	Label string `json:"label"`
}

// Field describes one setting of a module.
type Field struct {
	Name        string   `json:"name"`  // key in the settings map
	Label       string   `json:"label"` // shown in the web UI; defaults to Name
	Description string   `json:"description"`
	Type        string   `json:"type"`
	Default     string   `json:"default"`
	Placeholder string   `json:"placeholder"`
	Required    bool     `json:"required"`
	Options     []Option `json:"options"`
	// Min and Max bound a Number field. Both zero means no bounds.
	Min int `json:"min"`
	Max int `json:"max"`
}

// Settings are a module's configured values. They are always strings, as
// written in tamamo.yaml; the methods convert them.
type Settings map[string]string

// String returns the trimmed value of key.
func (s Settings) String(key string) string { return strings.TrimSpace(s[key]) }

// Int returns key as a whole number, or def when it is empty or not a number.
func (s Settings) Int(key string, def int) int {
	n, err := strconv.Atoi(s.String(key))
	if err != nil {
		return def
	}
	return n
}

// Bool reports whether key is true, 1, yes or on.
func (s Settings) Bool(key string) bool {
	b, _ := parseBool(s[key])
	return b
}

// Duration returns key parsed like "30s" or "5m" (a bare number is seconds),
// or def.
func (s Settings) Duration(key string, def time.Duration) time.Duration {
	v := s.String(key)
	if v == "" {
		return def
	}
	if n, err := strconv.Atoi(v); err == nil {
		return time.Duration(n) * time.Second
	}
	if d, err := time.ParseDuration(v); err == nil {
		return d
	}
	return def
}

// List splits key at line breaks and commas, dropping empty entries.
func (s Settings) List(key string) []string {
	out := []string{}
	for _, v := range strings.FieldsFunc(s[key], func(r rune) bool { return r == '\n' || r == '\r' || r == ',' }) {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func parseBool(v string) (value, ok bool) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "false", "0", "no", "off":
		return false, true
	case "true", "1", "yes", "on":
		return true, true
	}
	return false, false
}

// ---- registration -----------------------------------------------------------

// Page is one page a module adds to the web UI. It is shown inside the web
// UI in a frame, loaded from Info.UI.
type Page struct {
	ID    string `json:"id"`    // URL part: a-z, 0-9 and dashes
	Title string `json:"title"` // shown in the web UI's navigation
	// Path is the HTML file in Info.UI. Empty means "index.html".
	Path string `json:"path"`
}

// Info describes a module. Pass it to Register.
type Info struct {
	// ID names the module in tamamo.yaml ("module: <id>"): a-z, 0-9 and
	// dashes, starting with a letter or digit.
	ID          string `json:"id"`
	Name        string `json:"name"` // shown in the web UI; defaults to ID
	Description string `json:"description"`
	Version     string `json:"version"`
	Author      string `json:"author"`
	Homepage    string `json:"homepage"`

	// Settings describes the module's settings. The web UI builds the form
	// from it, and Tamamo checks saved values against it before New sees them.
	Settings []Field `json:"settings"`

	// Pages are the module's own pages in the web UI.
	Pages []Page `json:"pages"`
	// UI holds the files of Pages (HTML, CSS, JS, images). Only a signed-in
	// admin can load them. Usually an embed.FS, see fs.Sub.
	UI fs.FS `json:"-"`
	// Static holds files visitors may load: what the module adds to the
	// checking page. See PageRequest.AssetURL.
	Static fs.FS `json:"-"`

	// New creates the module with its settings. It also runs to check a
	// config before it is saved, so it must be cheap and free of side
	// effects: parse the settings, return an error for bad ones and leave
	// files, network and goroutines to Start.
	New func(ctx *Context) (Module, error) `json:"-"`
}

// Context is what Tamamo hands a module in New.
type Context struct {
	// Name is the instance's name in tamamo.yaml. One module can be switched
	// on several times under different names.
	Name string
	// Settings holds the configured values, with the defaults of
	// Info.Settings filled in.
	Settings Settings
	// Sites lists the site IDs the instance is limited to; empty = all.
	Sites []string
	// Logger writes to Tamamo's log, tagged with the module's name.
	Logger *slog.Logger
	// Validating is true when New only runs to check the config: the
	// returned module is thrown away and never started.
	Validating bool

	dataDir string
}

// NewContext builds a Context. Tamamo calls it; tests of a module can too.
// dataDir is the folder DataDir returns ("" for none).
func NewContext(name string, settings Settings, sites []string, dataDir string) *Context {
	if settings == nil {
		settings = Settings{}
	}
	return &Context{
		Name: name, Settings: settings, Sites: sites, dataDir: dataDir,
		Logger: slog.Default().With("module", name),
	}
}

// DataDir returns a folder that belongs to this instance
// (<data>/modules/<name>), creating it if needed. Call it from Start, not
// from New: while a config is only being checked there is no folder.
func (c *Context) DataDir() (string, error) {
	if c.dataDir == "" {
		return "", errors.New("no data folder is available (DataDir must be called from Start, not New)")
	}
	if err := os.MkdirAll(c.dataDir, 0o700); err != nil {
		return "", err
	}
	return c.dataDir, nil
}

var (
	idPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

	regMu    sync.RWMutex
	registry = map[string]Info{}
)

// ValidID reports whether id can name a module or an instance of one.
func ValidID(id string) bool { return idPattern.MatchString(id) }

// Register adds a module to this build. Call it from an init function. It
// panics on a mistake in info (bad or duplicate ID, no New, a broken
// settings description), so the mistake shows up at start, not in production.
func Register(info Info) {
	if err := checkInfo(&info); err != nil {
		panic("module.Register: " + err.Error())
	}
	regMu.Lock()
	defer regMu.Unlock()
	if _, dup := registry[info.ID]; dup {
		panic("module.Register: module " + strconv.Quote(info.ID) + " is registered twice")
	}
	registry[info.ID] = info
}

func checkInfo(info *Info) error {
	if !ValidID(info.ID) {
		return fmt.Errorf("ID %q must be a-z, 0-9 and dashes, starting with a letter or digit", info.ID)
	}
	if info.New == nil {
		return fmt.Errorf("module %q has no New function", info.ID)
	}
	if info.Name == "" {
		info.Name = info.ID
	}
	fields := make([]Field, len(info.Settings))
	seen := map[string]bool{}
	for i, f := range info.Settings {
		if f.Name == "" || seen[f.Name] {
			return fmt.Errorf("module %q: setting %d needs a name of its own", info.ID, i+1)
		}
		seen[f.Name] = true
		if f.Type == "" {
			f.Type = Text
		}
		switch f.Type {
		case Text, Secret, Number, Bool, TextArea, List:
		case Select:
			if len(f.Options) == 0 {
				return fmt.Errorf("module %q: select setting %q has no options", info.ID, f.Name)
			}
		default:
			return fmt.Errorf("module %q: setting %q has unknown type %q", info.ID, f.Name, f.Type)
		}
		if f.Label == "" {
			f.Label = f.Name
		}
		if f.Options == nil {
			f.Options = []Option{}
		}
		for j := range f.Options {
			if f.Options[j].Label == "" {
				f.Options[j].Label = f.Options[j].Value
			}
		}
		if f.Default != "" {
			if err := checkValue(&f, f.Default); err != nil {
				return fmt.Errorf("module %q: the default of %v", info.ID, err)
			}
		}
		fields[i] = f
	}
	info.Settings = fields
	pages := make([]Page, len(info.Pages))
	seen = map[string]bool{}
	for i, p := range info.Pages {
		if !ValidID(p.ID) || seen[p.ID] {
			return fmt.Errorf("module %q: page %d needs an ID of its own (a-z, 0-9, dashes)", info.ID, i+1)
		}
		seen[p.ID] = true
		if p.Title == "" {
			p.Title = p.ID
		}
		if p.Path == "" {
			p.Path = "index.html"
		}
		if !fs.ValidPath(p.Path) {
			return fmt.Errorf("module %q: page %q has a bad path %q", info.ID, p.ID, p.Path)
		}
		pages[i] = p
	}
	info.Pages = pages
	if len(pages) > 0 && info.UI == nil {
		return fmt.Errorf("module %q has pages but no UI files", info.ID)
	}
	return nil
}

// Registered lists the modules compiled into this build, sorted by ID.
func Registered() []Info {
	regMu.RLock()
	out := make([]Info, 0, len(registry))
	for _, info := range registry {
		out = append(out, info)
	}
	regMu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Lookup returns a registered module.
func Lookup(id string) (Info, bool) {
	regMu.RLock()
	defer regMu.RUnlock()
	info, ok := registry[id]
	return info, ok
}

// checkValue checks one non-empty value against its field.
func checkValue(f *Field, v string) error {
	switch f.Type {
	case Number:
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil {
			return fmt.Errorf("setting %q must be a whole number", f.Name)
		}
		if (f.Min != 0 || f.Max != 0) && (n < f.Min || n > f.Max) {
			return fmt.Errorf("setting %q must be from %d to %d", f.Name, f.Min, f.Max)
		}
	case Bool:
		if _, ok := parseBool(v); !ok {
			return fmt.Errorf("setting %q must be true or false", f.Name)
		}
	case Select:
		for _, o := range f.Options {
			if o.Value == v {
				return nil
			}
		}
		vals := make([]string, len(f.Options))
		for i, o := range f.Options {
			vals[i] = o.Value
		}
		return fmt.Errorf("setting %q must be one of: %s", f.Name, strings.Join(vals, ", "))
	}
	return nil
}

// Prepare checks settings against the module's description and returns a
// copy with the defaults filled in. Settings the description doesn't list
// are passed through untouched.
func (info *Info) Prepare(settings map[string]string) (Settings, error) {
	out := make(Settings, len(settings)+len(info.Settings))
	for k, v := range settings {
		out[k] = v
	}
	for i := range info.Settings {
		f := &info.Settings[i]
		if strings.TrimSpace(out[f.Name]) == "" {
			if f.Required {
				return nil, fmt.Errorf("setting %q is required", f.Name)
			}
			out[f.Name] = f.Default
			continue
		}
		if err := checkValue(f, out[f.Name]); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// Create builds one instance of the module: it checks ctx.Settings, fills in
// the defaults and calls New. Tamamo calls it; tests of a module can too.
func (info *Info) Create(ctx *Context) (Module, error) {
	s, err := info.Prepare(ctx.Settings)
	if err != nil {
		return nil, err
	}
	ctx.Settings = s
	m, err := safeNew(info, ctx)
	if err != nil {
		return nil, err
	}
	if m == nil {
		return nil, fmt.Errorf("module %q returned nothing from New", info.ID)
	}
	return m, nil
}

func safeNew(info *Info, ctx *Context) (m Module, err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("module %q panicked in New: %v", info.ID, p)
		}
	}()
	return info.New(ctx)
}

// InstanceDir returns the data folder of the instance name under the data
// directory dataDir ("" if dataDir is empty).
func InstanceDir(dataDir, name string) string {
	if dataDir == "" {
		return ""
	}
	return filepath.Join(dataDir, "modules", name)
}
