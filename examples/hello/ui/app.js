// The page's script. Inline scripts are refused by the web UI's content
// security policy, so it lives in its own file.
(function () {
  'use strict';

  var labels = {
    allow: 'Allowed', pass: 'Passed', challenge: 'Challenged',
    block: 'Blocked', solve: 'Solved', fail: 'Failed',
  };

  function el(tag, text, cls) {
    var e = document.createElement(tag);
    if (text !== undefined) e.textContent = text;
    if (cls) e.className = cls;
    return e;
  }

  function render(data) {
    var stats = document.getElementById('stats');
    stats.replaceChildren();
    Object.keys(labels).forEach(function (kind) {
      var box = el('div', undefined, 'tm-stat');
      box.append(el('b', String(data.events[kind] || 0)), el('span', labels[kind]));
      stats.append(box);
    });

    var rows = document.getElementById('paths');
    rows.replaceChildren();
    data.blocked.forEach(function (p) {
      var tr = el('tr');
      tr.append(el('td', p.path, 'tm-mono'), el('td', String(p.count), 'tm-num'));
      rows.append(tr);
    });
    document.getElementById('no-paths').hidden = data.blocked.length > 0;
  }

  function load() {
    // tamamo.api talks to this module's AdminHandler: GET /api/x/<name>/stats
    return tamamo.api('/stats').then(render).catch(function (err) {
      tamamo.toast(err.message, 'error');
    });
  }

  document.getElementById('refresh').addEventListener('click', load);
  document.getElementById('reset').addEventListener('click', function () {
    tamamo.api('/reset', { method: 'POST' }).then(function () {
      tamamo.toast('Counters reset', 'success');
      return load();
    }).catch(function (err) { tamamo.toast(err.message, 'error'); });
  });

  load();
})();
