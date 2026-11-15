// Package checks holds the request checks built into Tamamo that run before the
// rules: the bypass headers, the rate limit and the webhooks. They are
// configured in the protection settings.
package checks

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/foxgirlsorg/tamamo/module"
)

// Webhook limits.
const (
	DefaultWebhookTimeout = 500 * time.Millisecond
	MaxWebhookTimeout     = 10 * time.Second
	MaxWebhookCache       = time.Hour
	webhookCacheEntries   = 10000
	webhookMaxResponse    = 64 << 10
)

// WebhookOptions configures a webhook.
type WebhookOptions struct {
	URL     string
	Timeout time.Duration // 0 = DefaultWebhookTimeout
	// CacheTTL caches decisions per (site, ip, user agent, path); 0 = off.
	CacheTTL time.Duration
	// SendCookies includes the Cookie and Authorization headers in the
	// request to the webhook. Off by default: they carry visitors' sessions.
	SendCookies bool
	// Client overrides the HTTP client (tests).
	Client *http.Client
}

// WebhookRequest is the JSON body Tamamo POSTs to a webhook.
type WebhookRequest struct {
	Site      string            `json:"site"`
	Method    string            `json:"method"`
	Host      string            `json:"host"`
	Path      string            `json:"path"`
	Query     string            `json:"query"`
	UserAgent string            `json:"user_agent"`
	IP        string            `json:"ip"`
	Headers   map[string]string `json:"headers"`
}

// CheckWebhookURL accepts absolute http and https URLs only.
func CheckWebhookURL(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("webhook URL %q must be an http:// or https:// address", raw)
	}
	if u.User != nil {
		return errors.New("webhook URL must not contain user:password@")
	}
	return nil
}

// Webhook asks an HTTP endpoint about each request.
type Webhook struct {
	url     string
	client  *http.Client
	timeout time.Duration
	ttl     time.Duration
	cookies bool
	now     func() time.Time

	mu    sync.Mutex
	cache map[string]cachedDecision
}

type cachedDecision struct {
	d   module.Decision
	exp time.Time
}

var errRedirect = errors.New("webhook answered with a redirect")

// NewWebhook creates a webhook checker. Errors (non-2xx answers, bad JSON,
// timeouts) are returned to the caller, which applies the webhook's on_error.
func NewWebhook(o WebhookOptions) (*Webhook, error) {
	if err := CheckWebhookURL(o.URL); err != nil {
		return nil, err
	}
	if o.Timeout <= 0 {
		o.Timeout = DefaultWebhookTimeout
	}
	o.Timeout = min(o.Timeout, MaxWebhookTimeout)
	o.CacheTTL = min(max(o.CacheTTL, 0), MaxWebhookCache)
	c := o.Client
	if c == nil {
		c = &http.Client{
			Transport: http.DefaultTransport,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return errRedirect
			},
		}
	}
	return &Webhook{
		url: strings.TrimSpace(o.URL), client: c, timeout: o.Timeout, ttl: o.CacheTTL,
		cookies: o.SendCookies, now: time.Now, cache: map[string]cachedDecision{},
	}, nil
}

var secretHeaders = map[string]bool{"Cookie": true, "Authorization": true, "Proxy-Authorization": true}

func (wh *Webhook) Check(ctx context.Context, r *module.Request) (module.Decision, error) {
	ip := ""
	if r.IP.IsValid() {
		ip = r.IP.String()
	}
	key := r.Site + "\x00" + ip + "\x00" + r.UserAgent + "\x00" + r.Path
	if wh.ttl > 0 {
		if d, ok := wh.cached(key); ok {
			return d, nil
		}
	}

	body := WebhookRequest{
		Site: r.Site, Method: r.Method, Host: r.Host, Path: r.Path, Query: r.Query,
		UserAgent: r.UserAgent, IP: ip, Headers: map[string]string{},
	}
	for k, vs := range r.Header {
		if !wh.cookies && secretHeaders[http.CanonicalHeaderKey(k)] {
			continue
		}
		body.Headers[k] = strings.Join(vs, ", ")
	}
	b, _ := json.Marshal(body)

	ctx, cancel := context.WithTimeout(ctx, wh.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, wh.url, bytes.NewReader(b))
	if err != nil {
		return module.Decision{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Tamamo-Webhook/1")
	resp, err := wh.client.Do(req)
	if err != nil {
		return module.Decision{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, webhookMaxResponse))
		return module.Decision{}, fmt.Errorf("webhook answered %s", resp.Status)
	}
	var d module.Decision
	if err := json.NewDecoder(io.LimitReader(resp.Body, webhookMaxResponse)).Decode(&d); err != nil {
		return module.Decision{}, fmt.Errorf("webhook answer is not valid JSON: %w", err)
	}
	d.Action = strings.ToLower(strings.TrimSpace(d.Action))
	if d.Action == "continue" || d.Action == "none" {
		d.Action = module.NoOpinion
	}
	if !module.ValidAction(d.Action) {
		return module.Decision{}, fmt.Errorf("webhook answered with unknown action %q", d.Action)
	}
	if d.Difficulty < 0 || d.Difficulty > 8 {
		d.Difficulty = 0
	}
	if len(d.Reason) > 200 {
		d.Reason = d.Reason[:200]
	}
	if wh.ttl > 0 {
		wh.store(key, d)
	}
	return d, nil
}

func (wh *Webhook) cached(key string) (module.Decision, bool) {
	wh.mu.Lock()
	defer wh.mu.Unlock()
	c, ok := wh.cache[key]
	if !ok {
		return module.Decision{}, false
	}
	if !wh.now().Before(c.exp) {
		delete(wh.cache, key)
		return module.Decision{}, false
	}
	return c.d, true
}

func (wh *Webhook) store(key string, d module.Decision) {
	now := wh.now()
	wh.mu.Lock()
	defer wh.mu.Unlock()
	if len(wh.cache) >= webhookCacheEntries {
		for k, c := range wh.cache {
			if !now.Before(c.exp) {
				delete(wh.cache, k)
			}
		}
		drop := webhookCacheEntries / 8
		for k := range wh.cache {
			if len(wh.cache) < webhookCacheEntries-drop {
				break
			}
			delete(wh.cache, k)
		}
	}
	wh.cache[key] = cachedDecision{d: d, exp: now.Add(wh.ttl)}
}
