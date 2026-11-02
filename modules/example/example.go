// Package example is a sample Go module for Tamamo. It is not compiled into
// the binary unless cmd/tamamo/modules.go imports it.
//
// "path-block" refuses requests whose path starts with one of a list of
// prefixes, for example probes for software the site doesn't run:
//
//	{"type": "go", "name": "path-block", "enabled": true,
//	 "settings": {"prefixes": "/wp-admin, /wp-login.php, /.env"}}
package example

import (
	"context"
	"errors"
	"strings"

	"github.com/tamamo/tamamo/internal/modules"
)

func init() {
	modules.Register(modules.Info{
		Name:        "path-block",
		Description: "Blocks requests whose path starts with one of the given prefixes.",
		Settings: []modules.SettingInfo{
			{Name: "prefixes", Description: "Comma-separated path prefixes, e.g. /wp-admin, /.env", Required: true},
			{Name: "action", Description: "block or challenge.", Default: "block"},
		},
	}, newPathBlock)
}

type pathBlock struct {
	prefixes []string
	action   string
}

// newPathBlock is the factory: it validates the settings and returns the
// checker. It is also called when the config is saved, so a bad setting is
// reported to the admin instead of failing at request time.
func newPathBlock(s map[string]string) (modules.Checker, error) {
	pb := &pathBlock{action: s["action"]}
	if pb.action != modules.Block && pb.action != modules.Challenge {
		return nil, errors.New(`setting "action" must be block or challenge`)
	}
	for _, p := range strings.Split(s["prefixes"], ",") {
		if p = strings.TrimSpace(p); p != "" {
			if !strings.HasPrefix(p, "/") {
				return nil, errors.New("every prefix must start with /")
			}
			pb.prefixes = append(pb.prefixes, p)
		}
	}
	if len(pb.prefixes) == 0 {
		return nil, errors.New(`setting "prefixes" needs at least one path`)
	}
	return pb, nil
}

// Check returns an empty Decision ("no opinion") unless a prefix matches, so
// the next module and then the rules decide about every other request.
func (pb *pathBlock) Check(_ context.Context, r modules.Request) (modules.Decision, error) {
	for _, p := range pb.prefixes {
		if strings.HasPrefix(r.Path, p) {
			return modules.Decision{Action: pb.action, Reason: "path " + p}, nil
		}
	}
	return modules.Decision{}, nil
}
