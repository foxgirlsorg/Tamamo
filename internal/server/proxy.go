package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"strings"
	"sync"

	"github.com/foxgirlsorg/tamamo/internal/modules"
	"github.com/foxgirlsorg/tamamo/internal/page"
	"github.com/foxgirlsorg/tamamo/module"
)

type proxyKey struct {
	target   string
	insecure bool
}

// proxyCache holds one ReverseProxy (and so one connection pool) per
// upstream. It is emptied whenever the config changes.
type proxyCache struct {
	server *Server
	mu     sync.Mutex
	m      map[proxyKey]*cachedProxy
}

type cachedProxy struct {
	rp        *httputil.ReverseProxy
	transport *http.Transport
}

func newProxyCache() *proxyCache { return &proxyCache{m: map[proxyKey]*cachedProxy{}} }

func (c *proxyCache) reset() {
	c.mu.Lock()
	old := c.m
	c.m = map[proxyKey]*cachedProxy{}
	c.mu.Unlock()
	// In-flight requests keep using the old transports; only idle
	// connections are closed.
	for _, p := range old {
		p.transport.CloseIdleConnections()
	}
}

func (c *proxyCache) get(target string, insecure bool) (*httputil.ReverseProxy, error) {
	k := proxyKey{target, insecure}
	c.mu.Lock()
	defer c.mu.Unlock()
	if p := c.m[k]; p != nil {
		return p.rp, nil
	}
	p, err := c.server.newProxy(target, insecure)
	if err != nil {
		return nil, err
	}
	c.m[k] = p
	return p.rp, nil
}

type ctxKey struct{}

// proxyInfo carries per-request data into the Rewrite hook.
type proxyInfo struct {
	clientIP   netip.Addr
	cookieName string // the site's pass cookie, stripped before forwarding
	mods       []*modules.Instance
	req        *module.Request
	// sharedPass: the site accepts passes of other sites in PassHeader.
	sharedPass bool
}

// applies reports whether in's proxy hooks run for this request.
func (pi *proxyInfo) applies(in *modules.Instance) bool {
	return pi.req != nil && in.Cfg.AppliesTo(pi.req.Site)
}

// newProxy builds a reverse proxy for target, which is http(s)://host[:port][/path]
// or unix:///path/to.sock.
func (s *Server) newProxy(target string, insecure bool) (*cachedProxy, error) {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: insecure} //nolint:gosec // opt-in setting

	var u *url.URL
	if sock, ok := strings.CutPrefix(target, "unix://"); ok {
		if sock == "" {
			return nil, errors.New("empty unix socket path")
		}
		// The URL host is a placeholder; every connection goes to the socket.
		u = &url.URL{Scheme: "http", Host: "localhost"}
		var d net.Dialer
		tr.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			return d.DialContext(ctx, "unix", sock)
		}
		tr.ForceAttemptHTTP2 = false
	} else {
		var err error
		if u, err = url.Parse(target); err != nil {
			return nil, err
		}
	}

	rp := &httputil.ReverseProxy{
		Transport: tr,
		Rewrite: func(pr *httputil.ProxyRequest) {
			cfg := s.mgr.Get()
			pr.SetURL(u)
			// ReverseProxy drops query parameters it can't parse (e.g. ones
			// with ';', used by gitweb) before Rewrite; forward the query as
			// the client sent it.
			pr.Out.URL.RawQuery = pr.In.URL.RawQuery
			if u.RawQuery != "" {
				if pr.In.URL.RawQuery == "" {
					pr.Out.URL.RawQuery = u.RawQuery
				} else {
					pr.Out.URL.RawQuery = u.RawQuery + "&" + pr.In.URL.RawQuery
				}
			}
			pr.SetXForwarded()
			// Behind a proxy that terminates TLS, keep the scheme it reported
			// so the app still knows the visitor used https.
			if cfg.Server.IPSource != "remote" {
				if p := strings.ToLower(pr.In.Header.Get("X-Forwarded-Proto")); p == "http" || p == "https" {
					pr.Out.Header.Set("X-Forwarded-Proto", p)
				}
			}
			if cfg.Server.PreserveHost {
				pr.Out.Host = pr.In.Host
			}
			info, _ := pr.In.Context().Value(ctxKey{}).(*proxyInfo)
			if info == nil {
				info = &proxyInfo{cookieName: cfg.Protection.CookieName}
			}
			if info.clientIP.IsValid() {
				pr.Out.Header.Set("X-Real-IP", info.clientIP.String())
			} else {
				pr.Out.Header.Del("X-Real-IP")
			}
			stripCookie(pr.Out.Header, info.cookieName)
			pr.Out.Header.Del(PassHeader)
			for _, in := range info.mods {
				if in.ReqMod == nil || !info.applies(in) {
					continue
				}
				func() {
					defer func() {
						if p := recover(); p != nil {
							slog.Error("module panicked in ModifyRequest", "module", in.Cfg.Name, "panic", p)
						}
					}()
					in.ReqMod.ModifyRequest(pr.Out, info.req)
				}()
			}
		},
		ModifyResponse: func(resp *http.Response) error {
			info, _ := resp.Request.Context().Value(ctxKey{}).(*proxyInfo)
			if info == nil {
				return nil
			}
			// The app's answer to a browser's CORS question must name the
			// pass header, or the browser won't send it.
			if info.sharedPass && resp.Request.Method == http.MethodOptions && resp.Header.Get("Access-Control-Allow-Origin") != "" {
				allowed := resp.Header.Get("Access-Control-Allow-Headers")
				switch {
				case allowed == "":
					resp.Header.Set("Access-Control-Allow-Headers", PassHeader)
				case allowed != "*" && !strings.Contains(strings.ToLower(allowed), strings.ToLower(PassHeader)):
					resp.Header.Set("Access-Control-Allow-Headers", allowed+", "+PassHeader)
				}
			}
			for _, in := range info.mods {
				if in.RespMod == nil || !info.applies(in) {
					continue
				}
				if err := modifyResponse(in, resp, info.req); err != nil {
					return fmt.Errorf("module %s: %w", in.Cfg.Name, err)
				}
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			if errors.Is(err, context.Canceled) {
				// The client went away; nobody is listening for a reply.
				w.WriteHeader(http.StatusBadGateway)
				return
			}
			slog.Warn("upstream request failed", "target", target, "path", r.URL.Path, "err", err)
			s.render(w, r, http.StatusBadGateway, page.Data{State: "error", MessageID: "upstream_down"})
		},
	}
	return &cachedProxy{rp: rp, transport: tr}, nil
}

// modifyResponse runs a module's ResponseModifier, turning a panic into an error.
func modifyResponse(in *modules.Instance, resp *http.Response, req *module.Request) (err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("panic: %v", p)
		}
	}()
	return in.RespMod.ModifyResponse(resp, req)
}

// proxy forwards the request to the decision's site.
func (s *Server) proxy(w http.ResponseWriter, r *http.Request, dc *decision) {
	target, ip, cookieName := dc.site.Target, dc.ip, dc.site.Protection.CookieName
	cfg := s.mgr.Get()
	rp, err := s.proxies.get(target, cfg.Server.InsecureSkipVerify)
	if err != nil {
		slog.Error("bad upstream", "target", target, "err", err)
		s.render(w, r, http.StatusBadGateway, page.Data{State: "error", MessageID: "upstream_down"})
		return
	}
	r = r.WithContext(context.WithValue(r.Context(), ctxKey{}, &proxyInfo{clientIP: ip, cookieName: cookieName, mods: dc.d.mods, req: dc.req, sharedPass: len(dc.site.Trusts) > 0}))
	rp.ServeHTTP(w, r)
}

// stripCookie removes the named cookie from all Cookie header lines, so the
// upstream never sees Tamamo's pass.
func stripCookie(h http.Header, name string) {
	lines := h.Values("Cookie")
	if len(lines) == 0 || name == "" {
		return
	}
	var kept []string
	for _, line := range lines {
		var parts []string
		for _, part := range strings.Split(line, ";") {
			p := strings.TrimSpace(part)
			if p == "" {
				continue
			}
			n, _, _ := strings.Cut(p, "=")
			if strings.TrimSpace(n) == name {
				continue
			}
			parts = append(parts, p)
		}
		if len(parts) > 0 {
			kept = append(kept, strings.Join(parts, "; "))
		}
	}
	h.Del("Cookie")
	if len(kept) > 0 {
		// HTTP/1.1 requires a single Cookie line.
		h.Set("Cookie", strings.Join(kept, "; "))
	}
}
