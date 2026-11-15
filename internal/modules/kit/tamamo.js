// Tamamo module UI kit. Load it from a module's web UI page with
//   <script src="/assets/modules/kit/tamamo.js"></script>
// It defines window.tamamo. See the "Module UI" page of the documentation.
(function () {
  'use strict';

  var params = new URLSearchParams(location.search);
  var name = params.get('module') || '';
  var base = '/api/x/' + encodeURIComponent(name);
  var inFrame = window.parent !== window;

  function send(type, payload) {
    if (!inFrame) return;
    var msg = { source: 'tamamo-module', module: name, type: type };
    for (var k in payload) msg[k] = payload[k];
    window.parent.postMessage(msg, location.origin);
  }

  // api('/path') -> GET, api('/path', {body: {...}}) -> POST with JSON.
  // Resolves with the parsed JSON answer (or text); rejects with an Error
  // whose message is the server's {"error": "..."}.
  function api(path, options) {
    options = options || {};
    var headers = { 'X-Tamamo-Request': '1' };
    for (var h in options.headers || {}) headers[h] = options.headers[h];
    var body = options.body;
    if (body !== undefined && body !== null && typeof body !== 'string' &&
        !(body instanceof FormData) && !(body instanceof Blob) && !(body instanceof ArrayBuffer)) {
      body = JSON.stringify(body);
      headers['Content-Type'] = 'application/json';
    }
    var method = options.method || (body === undefined || body === null ? 'GET' : 'POST');
    return fetch(base + path, {
      method: method, headers: headers, body: body, credentials: 'same-origin', signal: options.signal,
    }).then(function (res) {
      return res.text().then(function (text) {
        var data = text;
        try { data = text ? JSON.parse(text) : null; } catch (e) { /* not JSON */ }
        if (!res.ok) {
          if (res.status === 401) send('unauthorized', {});
          var err = new Error((data && data.error) || res.statusText || ('HTTP ' + res.status));
          err.status = res.status;
          err.data = data;
          throw err;
        }
        return data;
      });
    });
  }

  window.tamamo = {
    // Name of this module entry in tamamo.yaml.
    module: name,
    // Language of the web UI: "en", "ru", "uk"...
    lang: params.get('lang') || 'en',
    // Base URL of the module's admin API (/api/x/<name>).
    apiBase: base,
    api: api,
    // Show a message in the web UI. kind: "info", "success" or "error".
    toast: function (message, kind) { send('toast', { message: String(message), kind: kind || 'info' }); },
    // Go to another screen of the web UI, e.g. tamamo.navigate('/modules').
    navigate: function (path) { send('navigate', { path: String(path) }); },
  };

  document.documentElement.lang = window.tamamo.lang;

  // Tell the web UI how tall the page is, so the frame grows with it.
  function reportHeight() {
    send('height', { height: Math.ceil(document.documentElement.getBoundingClientRect().height) });
  }
  if (inFrame) {
    if (typeof ResizeObserver === 'function') {
      new ResizeObserver(reportHeight).observe(document.documentElement);
    }
    window.addEventListener('load', reportHeight);
    reportHeight();
  }
})();
