/*
 * Tamamo challenge page logic. Plain ES2017, no dependencies.
 *
 * Reads #tm-data, solves the proof-of-work in Web Workers (main-thread
 * fallback), posts the answer to the verify endpoint and redirects.
 * In preview mode (admin live preview) it never posts or redirects; the parent
 * window can switch states with
 *   iframe.contentWindow.postMessage({type: 'tamamo-preview-state', state: 'success'}, '*')
 */
(function () {
  'use strict';

  var doc = document;
  var STATES = { checking: 1, success: 1, denied: 1, error: 1 };
  var CREDIT_TEXT = 'Protected by Tamamo';
  var RING_C = 169.65;

  function $(id) { return doc.getElementById(id); }

  var D = {};
  try { D = JSON.parse(($('tm-data') || {}).textContent || '{}') || {}; } catch (e) { D = {}; }
  D.texts = D.texts || {};
  D.images = D.images || {};

  // Page labels (translated by the server); English if missing.
  var L = D.labels || {};
  var EN = {
    seconds: 's', minutes: 'min', hash_rate: 'H/s', hash_rate_k: 'kH/s', hash_rate_m: 'MH/s',
    cookies_disabled: 'Cookies are turned off in this browser. Tamamo needs a cookie to remember that you passed the check. Please enable cookies for this site and try again.',
    browser_too_old: 'This browser is too old to run the check. Please update it and try again.',
    data_missing: 'The challenge data is missing. Please reload the page.',
    solver_failed: 'The check could not run in this browser ({error}). Please reload the page.',
    too_many_attempts: 'Too many attempts. Please wait a minute, then try again.',
    network_error: 'Could not reach the server. Check your connection and try again.',
    server_rejected: 'The server rejected the check (HTTP {status}).'
  };
  function label(key, vars) {
    var t = L[key] || EN[key] || '';
    if (vars) {
      Object.keys(vars).forEach(function (k) { t = t.split('{' + k + '}').join(String(vars[k])); });
    }
    return t;
  }

  var pageStart = now();
  function now() { return (typeof performance !== 'undefined' && performance.now) ? performance.now() : Date.now(); }

  /* ---------------------------------------------------------------- credit */

  var creditStyle = '';
  (function () {
    var f = doc.querySelector('footer.tm-credit');
    if (f) creditStyle = f.getAttribute('style') || '';
    if (!creditStyle) {
      creditStyle = 'display:flex !important;align-items:center !important;justify-content:center !important;gap:6px !important;' +
        'visibility:visible !important;opacity:1 !important;position:relative !important;transform:none !important;' +
        'clip-path:none !important;filter:none !important;font-size:13px !important;height:auto !important;' +
        'max-height:none !important;overflow:visible !important;margin:0 !important;padding:14px 20px 18px !important;' +
        'color:#71717a !important;z-index:2147483647 !important';
    }
  })();

  function buildCredit() {
    var f = doc.createElement('footer');
    f.className = 'tm-credit';
    f.setAttribute('style', creditStyle);
    var span = doc.createElement('span');
    span.setAttribute('style', 'display:inline !important;visibility:visible !important;opacity:1 !important;font-size:inherit !important;color:inherit !important');
    span.appendChild(doc.createTextNode('Protected by '));
    var strong = doc.createElement('strong');
    strong.setAttribute('style', 'display:inline !important;font-weight:700 !important;color:inherit !important;font-size:inherit !important');
    strong.textContent = 'Tamamo';
    span.appendChild(strong);
    f.appendChild(span);
    return f;
  }

  function alpha(color) {
    var m = /rgba?\(([^)]+)\)/.exec(color || '');
    if (!m) return color === 'transparent' ? 0 : 1;
    var parts = m[1].split(/[\s,\/]+/).filter(Boolean);
    if (parts.length < 4) return 1;
    var a = parts[3];
    return a.indexOf('%') >= 0 ? parseFloat(a) / 100 : parseFloat(a);
  }

  function creditOK(f) {
    var body = doc.body;
    if (!f || !body || f.parentNode !== body) return false;
    if ((f.textContent || '').replace(/\s+/g, ' ').trim() !== CREDIT_TEXT) return false;
    if (f.getAttribute('style') !== creditStyle) return false;
    var r = f.getBoundingClientRect();
    if (r.width < 60 || r.height < 12) return false;
    var cs = getComputedStyle(f);
    if (cs.display === 'none' || cs.visibility !== 'visible' || parseFloat(cs.fontSize) < 11 || alpha(cs.color) < 0.5) return false;
    for (var el = f; el && el.nodeType === 1; el = el.parentElement) {
      var s = getComputedStyle(el);
      if (s.display === 'none' || parseFloat(s.opacity) < 0.9) return false;
    }
    var span = f.querySelector('span');
    if (span) {
      var sr = span.getBoundingClientRect();
      if (sr.width < 40 || sr.height < 8) return false;
    }
    // Covered by something else? Only checkable while on screen.
    var cx = r.left + r.width / 2, cy = r.top + r.height / 2;
    if (cy > 0 && cy < innerHeight && cx > 0 && cx < innerWidth && doc.elementFromPoint) {
      var hit = doc.elementFromPoint(cx, cy);
      if (hit && hit !== f && !f.contains(hit) && hit !== body && hit !== doc.documentElement) return false;
    }
    return true;
  }

  function guardCredit() {
    var body = doc.body;
    if (!body) return;
    var all = doc.querySelectorAll('footer.tm-credit');
    var f = all.length ? all[all.length - 1] : null;
    if (creditOK(f)) {
      if (f.nextElementSibling) body.appendChild(f); // keep it last
      return;
    }
    // Unhide the page roots if a stylesheet hid them, then rebuild.
    [doc.documentElement, body].forEach(function (el) {
      var s = getComputedStyle(el);
      if (s.display === 'none') el.style.setProperty('display', el === body ? 'flex' : 'block', 'important');
      if (s.visibility !== 'visible') el.style.setProperty('visibility', 'visible', 'important');
      if (parseFloat(s.opacity) < 0.9) el.style.setProperty('opacity', '1', 'important');
    });
    for (var i = 0; i < all.length; i++) {
      if (all[i].parentNode) all[i].parentNode.removeChild(all[i]);
    }
    body.appendChild(buildCredit());
  }

  /* -------------------------------------------------------------- elements */

  var el = {
    body: doc.body,
    heading: $('tm-heading'),
    message: $('tm-message'),
    live: $('tm-live'),
    figure: $('tm-figure'),
    mascot: $('tm-mascot'),
    progress: $('tm-progress'),
    fill: $('tm-fill'),
    ringPct: $('tm-ring-pct'),
    diff: $('tm-s-difficulty'),
    rate: $('tm-s-rate'),
    elapsed: $('tm-s-elapsed'),
    percent: $('tm-s-percent'),
    actions: $('tm-actions'),
    retry: $('tm-retry'),
    cont: $('tm-continue')
  };

  var current = el.body ? el.body.getAttribute('data-state') : 'checking';
  if (!STATES[current]) current = 'checking';

  // Preload the other mascot poses so state swaps are instant.
  ['checking', 'success', 'denied'].forEach(function (k) {
    if (D.images[k]) { var im = new Image(); im.src = D.images[k]; }
  });

  /* ----------------------------------------------------------------- state */

  function setState(state, message, announce) {
    if (!STATES[state]) return;
    var t = D.texts[state] || {};
    var changed = state !== current;
    current = state;
    el.body.setAttribute('data-state', state);
    if (el.heading) el.heading.textContent = t.heading || '';
    if (el.message) el.message.textContent = message || t.message || '';

    if (el.figure && el.mascot) {
      var src = D.images[state === 'error' ? 'denied' : state] || '';
      if (!src) {
        el.figure.hidden = true;
      } else {
        el.figure.hidden = false;
        if (el.mascot.getAttribute('src') !== src) {
          el.mascot.setAttribute('src', src);
          if (changed) {
            el.mascot.classList.remove('tm-pop');
            void el.mascot.offsetWidth;
            el.mascot.classList.add('tm-pop');
          }
        }
      }
    }

    var showRetry = state === 'error';
    var showCont = state === 'success' && !D.auto_redirect;
    if (el.retry) el.retry.hidden = !showRetry;
    if (el.cont) el.cont.hidden = !showCont;
    if (el.actions) el.actions.hidden = !(showRetry || showCont);

    if (state === 'success') setProgress(1);
    else if (state === 'checking') setProgress(0);

    if (announce !== false && el.live) {
      el.live.textContent = '';
      var h = (t.heading || '').trim();
      var text = h + (h && !/[.!?…:]$/.test(h) ? '. ' : ' ') + (message || t.message || '');
      setTimeout(function () { el.live.textContent = text; }, 60);
    }
  }

  var lastPct = -1;
  function setProgress(p) {
    p = Math.max(0, Math.min(1, p));
    if (el.fill) {
      if (D.progress === 'ring') el.fill.style.strokeDashoffset = String(RING_C * (1 - p));
      else el.fill.style.transform = 'scaleX(' + p + ')';
    }
    var pct = Math.floor(p * 100);
    if (pct !== lastPct) {
      lastPct = pct;
      if (el.ringPct) el.ringPct.textContent = pct + '%';
      if (el.percent) el.percent.textContent = pct + '%';
      if (el.progress && el.progress.hasAttribute('aria-valuenow')) el.progress.setAttribute('aria-valuenow', String(pct));
    }
  }

  function fmtRate(hps) {
    if (!(hps > 0)) return '–';
    if (hps >= 1e6) return (hps / 1e6).toFixed(2) + ' ' + label('hash_rate_m');
    if (hps >= 1e3) return (hps / 1e3).toFixed(hps >= 1e5 ? 0 : 1) + ' ' + label('hash_rate_k');
    return Math.round(hps) + ' ' + label('hash_rate');
  }

  function fmtElapsed(ms) {
    var s = ms / 1000;
    var sec = label('seconds');
    if (s < 60) return s.toFixed(1) + ' ' + sec;
    return Math.floor(s / 60) + ' ' + label('minutes') + ' ' + Math.floor(s % 60) + ' ' + sec;
  }

  function setStats(rate, elapsedMs) {
    if (el.rate) el.rate.textContent = fmtRate(rate);
    if (el.elapsed) el.elapsed.textContent = fmtElapsed(elapsedMs);
  }

  // Probability that a solution was found after `hashes` attempts.
  function probability(hashes, difficulty) {
    var p = 1 - Math.exp(-hashes / Math.pow(16, difficulty));
    return Math.min(p, 0.95);
  }

  /* ------------------------------------------------------------- redirects */

  function safeRedirect(u) {
    if (typeof u !== 'string' || !u) return D.redirect || '/';
    if (u.charAt(0) === '/' && u.charAt(1) !== '/' && u.charAt(1) !== '\\') return u;
    try {
      var url = new URL(u, location.href);
      if (url.origin === location.origin) return url.pathname + url.search + url.hash;
    } catch (e) { /* ignore */ }
    return '/';
  }

  function wireButtons() {
    if (el.retry) {
      el.retry.addEventListener('click', function (ev) {
        ev.preventDefault();
        if (!D.preview) location.reload();
      });
    }
    if (el.cont && D.preview) {
      el.cont.addEventListener('click', function (ev) { ev.preventDefault(); });
    }
  }

  /* ---------------------------------------------------------------- solver */

  function loadScript(src, cb) {
    if (window.TamamoPoW) { cb(null); return; }
    var s = doc.createElement('script');
    s.src = src;
    s.async = true;
    s.onload = function () { cb(window.TamamoPoW ? null : new Error('solver unavailable')); };
    s.onerror = function () { cb(new Error('could not load the solver')); };
    (doc.head || doc.body).appendChild(s);
  }

  // solve calls onProgress(totalHashes) periodically and onDone(err, nonce).
  function solve(random, difficulty, onProgress, onDone) {
    var finished = false, total = 0, workers = [], fellBack = false, sawMessage = false;
    var n = Math.max(1, Math.min(8, (navigator.hardwareConcurrency || 2) - 1));

    function finish(err, nonce) {
      if (finished) return;
      finished = true;
      stopWorkers();
      onDone(err, nonce);
    }
    function stopWorkers() {
      for (var i = 0; i < workers.length; i++) { try { workers[i].terminate(); } catch (e) { /* ignore */ } }
      workers = [];
    }
    function fallback() {
      if (fellBack || finished) return;
      fellBack = true;
      stopWorkers();
      mainThread();
    }

    function mainThread() {
      loadScript(D.worker_url, function (err) {
        if (err) { finish(err); return; }
        var search = new window.TamamoPoW.Search(random, difficulty, 0, 1);
        (function step() {
          if (finished) return;
          var until = now() + 14;
          while (now() < until) {
            var r = search.run(1500);
            total += search.last;
            if (r !== null) { onProgress(total); finish(null, r); return; }
          }
          onProgress(total);
          setTimeout(step, 0);
        })();
      });
    }

    if (typeof Worker === 'undefined') { mainThread(); return; }
    try {
      for (var i = 0; i < n; i++) {
        var w = new Worker(D.worker_url);
        w.onmessage = function (ev) {
          var m = ev.data || {};
          sawMessage = true;
          if (finished) return;
          if (m.type === 'progress') { total += m.hashes || 0; onProgress(total); }
          else if (m.type === 'found') { total += m.hashes || 0; onProgress(total); finish(null, String(m.nonce)); }
          else if (m.type === 'error') { fallback(); }
        };
        w.onerror = function (ev) {
          if (ev && ev.preventDefault) ev.preventDefault();
          fallback();
        };
        w.postMessage({ random: random, difficulty: difficulty, start: i, step: n });
        workers.push(w);
      }
    } catch (e) {
      fallback();
      return;
    }
    // If the workers never speak (blocked silently), solve here instead.
    setTimeout(function () { if (!sawMessage) fallback(); }, 4000);
  }

  /* ------------------------------------------------------------------ flow */

  function fail(message) {
    stopTicker();
    setState('error', message);
  }

  var ticker = null;
  function stopTicker() { if (ticker) { clearInterval(ticker); ticker = null; } }

  function runChallenge() {
    if (!navigator.cookieEnabled) {
      fail(label('cookies_disabled'));
      return;
    }
    if (typeof fetch !== 'function' || typeof Promise === 'undefined') {
      fail(label('browser_too_old'));
      return;
    }
    if (!D.random || !D.token) {
      fail(label('data_missing'));
      return;
    }
    var difficulty = Math.max(1, Math.min(8, D.difficulty | 0));
    var start = now(), hashes = 0, rate = 0, lastT = start, lastH = 0;

    ticker = setInterval(function () {
      var t = now();
      var dt = t - lastT;
      if (dt >= 400) {
        var inst = (hashes - lastH) * 1000 / dt;
        rate = rate ? rate * 0.6 + inst * 0.4 : inst;
        lastT = t;
        lastH = hashes;
      }
      setProgress(probability(hashes, difficulty));
      setStats(rate, t - start);
    }, 100);

    solve(D.random, difficulty, function (h) { hashes = h; }, function (err, nonce) {
      stopTicker();
      if (err) { fail(label('solver_failed', { error: err.message })); return; }
      var elapsed = Math.round(now() - start);
      setStats(elapsed > 0 ? hashes * 1000 / elapsed : rate, elapsed);
      setProgress(0.95);
      verify(nonce, elapsed);
    });
  }

  function verify(nonce, elapsed) {
    fetch(D.verify_url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify({ token: D.token, nonce: nonce, elapsed_ms: elapsed, redirect: D.redirect })
    }).then(function (res) {
      return res.json().catch(function () { return {}; }).then(function (body) {
        return { status: res.status, ok: res.ok, body: body || {} };
      });
    }).then(function (r) {
      var wait = Math.max(0, (D.min_display_ms || 0) - (now() - pageStart));
      setTimeout(function () {
        if (r.ok && r.body.ok) { succeed(r.body.redirect || D.redirect); return; }
        if (r.status === 429) { fail(label('too_many_attempts')); return; }
        fail(r.body.error || label('server_rejected', { status: r.status }));
      }, wait);
    }).catch(function () {
      fail(label('network_error'));
    });
  }

  function succeed(redirect) {
    var target = safeRedirect(redirect);
    if (el.cont) el.cont.setAttribute('href', target);
    setState('success');
    if (D.auto_redirect) {
      setTimeout(function () { location.replace(target); }, Math.max(0, D.success_delay_ms || 0));
    } else if (el.cont) {
      try { el.cont.focus({ preventScroll: true }); } catch (e) { el.cont.focus(); }
    }
  }

  /* --------------------------------------------------------------- preview */

  var fake = null;
  function startFake() {
    stopFake();
    var difficulty = Math.max(1, Math.min(8, D.difficulty | 0 || 4));
    if (el.diff) el.diff.textContent = String(difficulty);
    var cycle = 5200, hold = 900, t0 = now(), base = 1.6e6 + Math.random() * 1.2e6, rate = base;
    fake = setInterval(function () {
      var t = now() - t0;
      if (t > cycle + hold) { t0 = now(); t = 0; base = 1.6e6 + Math.random() * 1.2e6; }
      var run = Math.min(t, cycle);
      rate = rate * 0.7 + base * (0.92 + Math.random() * 0.16) * 0.3;
      setProgress(0.95 * (1 - Math.exp(-3.2 * run / cycle)));
      setStats(rate, run);
    }, 100);
  }
  function stopFake() { if (fake) { clearInterval(fake); fake = null; } }

  function runPreview() {
    setState(current, null, false);
    if (current === 'checking') startFake();
    else if (current === 'success') setStats(2.1e6, 1800);
    window.addEventListener('message', function (ev) {
      if (ev.source !== window.parent || window.parent === window) return;
      var m = ev.data;
      if (!m || m.type !== 'tamamo-preview-state' || !STATES[m.state]) return;
      stopFake();
      setState(m.state);
      if (m.state === 'checking') startFake();
      else if (m.state === 'success') setStats(2.1e6, 1800);
    });
  }

  /* ------------------------------------------------------------------ boot */

  function boot() {
    if (!el.body) return;
    guardCredit();
    setInterval(guardCredit, 2000);
    wireButtons();
    if (D.preview) { runPreview(); return; }
    if (current === 'checking') runChallenge();
  }

  if (doc.readyState === 'loading') doc.addEventListener('DOMContentLoaded', boot);
  else boot();
})();
