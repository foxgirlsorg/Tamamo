// Package modules is Tamamo's extension system.
//
// There are three kinds of module, all switched on in the "modules" section
// of the config:
//
//   - "go" modules are compiled into the binary. They implement Checker and
//     register themselves with Register from an init function. Two ship with
//     Tamamo: "ratelimit" and "bypass-header".
//   - "webhook" modules ask an HTTP endpoint about each request (see
//     NewWebhook).
//   - "page" modules are folders under <data>/modules/<name>/ whose files are
//     added to the checking page (see LoadPage).
//
// Check modules (go and webhook) run in config order before the rules; the
// first one that returns a non-empty Action decides what happens.
//
// # Writing a Go module
//
// Create a package (for example modules/mymodule in this repository) with a
// file like this:
//
//	package mymodule
//
//	import (
//		"context"
//		"strings"
//
//		"github.com/tamamo/tamamo/internal/modules"
//	)
//
//	func init() {
//		modules.Register(modules.Info{
//			Name:        "block-wp-admin",
//			Description: "Blocks /wp-admin on sites that aren't WordPress.",
//		}, func(settings map[string]string) (modules.Checker, error) {
//			return modules.CheckerFunc(func(ctx context.Context, r modules.Request) (modules.Decision, error) {
//				if strings.HasPrefix(r.Path, "/wp-admin") {
//					return modules.Decision{Action: modules.Block, Reason: "not WordPress"}, nil
//				}
//				return modules.Decision{}, nil
//			}), nil
//		})
//	}
//
// then add a blank import of it to cmd/tamamo/modules.go and rebuild. The
// module shows up in GET /api/modules and can be switched on with
// {"type": "go", "name": "block-wp-admin", "enabled": true}.
package modules

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// Actions a Decision can take. The empty action means "no opinion": the next
// module (and then the rules) decide.
const (
	NoOpinion = ""
	Allow     = "allow"
	Challenge = "challenge"
	Block     = "block"
)

// Request is what a module sees of one request. Header is the live request
// header: treat it as read-only.
type Request struct {
	Site      string // site ID ("default" for the default site)
	Method    string
	Host      string // lower-case, without port
	Path      string
	Query     string // raw query, without "?"
	UserAgent string
	IP        netip.Addr // client address (may be invalid if unknown)
	Header    http.Header
}

// Decision is a module's answer.
type Decision struct {
	// Action is "" (no opinion), "allow", "challenge" or "block".
	Action string `json:"action"`
	// Difficulty is the proof-of-work difficulty for "challenge" (1-8);
	// 0 means the site's default.
	Difficulty int `json:"difficulty"`
	// Reason is a short explanation for logs.
	Reason string `json:"reason"`
}

// Checker looks at a request and decides about it. Check is called
// concurrently and must be safe for that.
type Checker interface {
	Check(ctx context.Context, r Request) (Decision, error)
}

// CheckerFunc adapts a function to Checker.
type CheckerFunc func(ctx context.Context, r Request) (Decision, error)

// Check calls f.
func (f CheckerFunc) Check(ctx context.Context, r Request) (Decision, error) { return f(ctx, r) }

// SettingInfo documents one setting of a Go module.
type SettingInfo struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Default     string `json:"default"`
	Required    bool   `json:"required"`
}

// Info describes a Go module.
type Info struct {
	Name        string        `json:"name"`
	Description string        `json:"description"`
	Settings    []SettingInfo `json:"settings"`
}

// Factory creates a configured Checker. It is also called to validate the
// config, so it should be cheap and must not start goroutines.
type Factory func(settings map[string]string) (Checker, error)

type entry struct {
	info    Info
	factory Factory
}

var (
	regMu    sync.RWMutex
	registry = map[string]entry{}
)

// Register adds a Go module. Call it from an init function. It panics on an
// empty or duplicate name or a nil factory.
func Register(info Info, factory func(settings map[string]string) (Checker, error)) {
	if strings.TrimSpace(info.Name) == "" || factory == nil {
		panic("modules: Register needs a name and a factory")
	}
	regMu.Lock()
	defer regMu.Unlock()
	if _, dup := registry[info.Name]; dup {
		panic("modules: module " + strconv.Quote(info.Name) + " is registered twice")
	}
	if info.Settings == nil {
		info.Settings = []SettingInfo{}
	}
	registry[info.Name] = entry{info: info, factory: factory}
}

// Available lists the registered Go modules, sorted by name.
func Available() []Info {
	regMu.RLock()
	out := make([]Info, 0, len(registry))
	for _, e := range registry {
		out = append(out, e.info)
	}
	regMu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Lookup returns a registered module's info.
func Lookup(name string) (Info, bool) {
	regMu.RLock()
	defer regMu.RUnlock()
	e, ok := registry[name]
	return e.info, ok
}

// New creates the Go module name with settings. Missing settings get their
// documented defaults; missing required settings are an error.
func New(name string, settings map[string]string) (Checker, error) {
	regMu.RLock()
	e, ok := registry[name]
	regMu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("no Go module named %q is compiled into this build", name)
	}
	s := make(map[string]string, len(settings)+len(e.info.Settings))
	for k, v := range settings {
		s[k] = v
	}
	for _, si := range e.info.Settings {
		if strings.TrimSpace(s[si.Name]) == "" {
			if si.Required {
				return nil, fmt.Errorf("setting %q is required", si.Name)
			}
			s[si.Name] = si.Default
		}
	}
	c, err := e.factory(s)
	if err != nil {
		return nil, err
	}
	if c == nil {
		return nil, fmt.Errorf("module %q returned no checker", name)
	}
	return c, nil
}

// IntSetting parses settings[key] as an integer in [lo, hi]; empty means def.
func IntSetting(settings map[string]string, key string, def, lo, hi int) (int, error) {
	v := strings.TrimSpace(settings[key])
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < lo || n > hi {
		return 0, fmt.Errorf("setting %q must be a whole number from %d to %d", key, lo, hi)
	}
	return n, nil
}

// ValidAction reports whether a is an action a Decision may carry.
func ValidAction(a string) bool {
	switch a {
	case NoOpinion, Allow, Challenge, Block:
		return true
	}
	return false
}
