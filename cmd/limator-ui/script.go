package main

const script = `
var statusBox = document.getElementById('status'), report = null, changes = null, deps = null, timer = null, shown = 300;
function $(id) { return document.getElementById(id); }
function el(tag, cls, text) {
  var e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined && text !== null) e.textContent = text;
  return e;
}
function url(path) { return path + '?t=' + encodeURIComponent(token); }
function busy(on, what) {
  document.querySelectorAll('main button').forEach(function (b) { b.disabled = on; });
  clearInterval(timer);
  if (!on) return;
  var start = Date.now();
  statusBox.textContent = what + '...';
  timer = setInterval(function () { statusBox.textContent = what + '... ' + Math.round((Date.now() - start) / 1000) + ' s'; }, 1000);
}
function done(text) { busy(false); statusBox.textContent = text; }
function get(name, what) {
  busy(true, what);
  return fetch(url('/data/' + name)).then(function (r) {
    if (!r.ok) return r.text().then(function (t) { throw new Error(t); });
    return r.json();
  }).then(function (data) { done('Done.'); return data; }, function (e) { done('Failed: ' + e.message); throw e; });
}
function post(path, fields, what) {
  var body = Object.keys(fields).map(function (k) { return k + '=' + encodeURIComponent(fields[k]); }).join('&');
  busy(true, what);
  return fetch(url(path), {method: 'POST', headers: {'Content-Type': 'application/x-www-form-urlencoded'}, body: body})
    .then(function (r) { return r.text().then(function (t) { done(t || (r.ok ? 'Done.' : 'Failed.')); if (!r.ok) throw new Error(t); return t; }); },
      function (e) { done('Failed: ' + e.message); throw e; });
}
function quiet() {}
function row(parts) {
  var r = el('div', 'row');
  parts.forEach(function (p) { if (p) r.append(p); });
  return r;
}
function fill(box, count, items, render, total) {
  box.textContent = '';
  items.slice(0, shown).forEach(function (item) { box.append(render(item)); });
  count.textContent = 'Showing ' + Math.min(shown, items.length) + ' of ' + items.length +
    (total !== undefined ? ' (' + total + ' in total)' : '') + '. Narrow the filter to see the rest.';
}
function has(text, needle) { return !needle || text.toLowerCase().indexOf(needle.toLowerCase()) >= 0; }
function exceptButton(rule, file) {
  var b = el('button', 'small', 'Exception');
  b.onclick = function () {
    var reason = window.prompt('Why is ' + rule + ' acceptable in ' + file + '? The reason is stored in the config.');
    if (reason === null) return;
    post('/except', {rule: rule, path: file, reason: reason}, 'Adding exception').then(function () { report = null; }, quiet);
  };
  return b;
}
function show(tab) {
  document.querySelectorAll('main section').forEach(function (s) { s.hidden = s.id !== tab; });
  document.querySelectorAll('#tabs button').forEach(function (b) { b.setAttribute('aria-selected', b.dataset.tab === tab); });
  if ((tab === 'overview' || tab === 'findings') && !report) loadReport();
}
function loadReport() {
  return get('report', 'Scanning').then(function (data) { report = data; overview(); findings(); }, quiet);
}
function card(label, value) {
  var c = el('div', 'card');
  c.append(el('b', '', value), el('span', 'dim', label));
  return c;
}
function overview() {
  var counts = report.counts || {}, total = 0;
  Object.keys(counts).forEach(function (k) { total += counts[k]; });
  var cards = $('cards'), rules = $('rules'), pick = $('frule');
  cards.textContent = ''; rules.textContent = ''; pick.textContent = '';
  cards.append(card('files', report.files), card('findings', total),
    card('exceptions', (report.exceptions || []).length), card('hash', (report.hash || '').slice(0, 12)));
  pick.append(new Option('All rules', ''));
  (report.rules || []).forEach(function (rule) {
    var n = counts[rule.id] || 0;
    if (!n) return;
    pick.append(new Option(rule.id + ' ' + rule.name + ' (' + n + ')', rule.id));
    var open = el('button', 'small', 'Show');
    open.onclick = function () { pick.value = rule.id; show('findings'); findings(); };
    rules.append(row([el('span', 'id', rule.id), el('span', 'where', rule.name), el('span', 'num', n), open]));
  });
  if (!total) rules.append(el('div', 'dim', 'No findings.'));
}
function findings() {
  if (!report) return;
  var rule = $('frule').value, needle = $('fpath').value;
  var items = (report.findings || []).filter(function (f) { return (!rule || f.rule === rule) && has(f.file + ' ' + f.msg, needle); });
  fill($('flist'), $('fcount'), items, function (f) {
    return row([el('span', 'id', f.rule), el('span', 'where', f.file + ':' + f.line), exceptButton(f.rule, f.file), el('span', 'code dim', f.msg)]);
  }, (report.findings || []).length);
}
function loadChanges() {
  return get('changes', 'Working out the fix').then(function (data) { changes = data; changeList(); reviewList(); }, quiet);
}
function changeList() {
  if (!changes) return;
  var needle = $('cpath').value;
  var items = (changes.changes || []).filter(function (c) { return c.kind !== 'review' && has(c.file, needle); });
  fill($('clist'), $('ccount'), items, function (c) {
    return row([el('span', 'id', c.kind), el('span', 'where', c.file + ':' + c.line),
      el('span', 'code old', c.before), c.after ? el('span', 'code new', c.after) : null]);
  });
  $('ccount').textContent = changes.files + ' files, ' + changes.cleaned + ' rewritten, ' + changes.removed + ' removed, ' +
    changes.review + ' left for review, ' + changes.skipped + ' skipped. ' + $('ccount').textContent;
}
function reviewList() {
  if (!changes) return;
  var needle = $('rpath').value;
  var items = (changes.changes || []).filter(function (c) { return c.kind === 'review' && has(c.file, needle); });
  fill($('rlist'), $('rcount'), items, function (c) {
    return row([el('span', 'where', c.file + ':' + c.line), exceptButton('L001', c.file), el('span', 'code', c.before)]);
  });
}
function readingList(units) {
  var box = $('llist');
  box.textContent = '';
  if (!units.length) box.append(el('div', 'dim', 'Nothing left to read.'));
  units.forEach(function (u) {
    var mark = el('button', 'small', 'Mark as read');
    var r = row([el('span', 'id', u.score), el('span', 'where', u.file + ':' + u.line + '  ' + u.func),
      el('span', 'dim', (u.sensitive || []).join(' ') + '  complexity ' + u.complexity + ', findings ' + u.findings), mark]);
    mark.onclick = function () { post('/run', {a: 'read', file: u.file, fn: u.func}, 'Marking').then(function () { r.remove(); }, quiet); };
    box.append(r);
  });
}
function fact(box, name, value) { box.append(row([el('span', 'where', name), el('span', '', value)])); }
function auditView(a) {
  var box = $('alist'), r = a.reading || {};
  box.textContent = '';
  fact(box, 'Version', a.version);
  fact(box, 'Files / lines', a.files + ' / ' + a.lines);
  fact(box, 'Dependencies', a.dependencies);
  fact(box, 'Licenses', Object.keys(a.licenses || {}).sort().map(function (k) { return k + ' ' + a.licenses[k]; }).join(', '));
  fact(box, 'Functions read', r.functions_read + ' of ' + r.functions);
  fact(box, 'Sensitive functions read', r.sensitive_functions_read + ' of ' + r.sensitive_functions);
  fact(box, 'AI-written functions read', r.ai_functions_read + ' of ' + r.ai_functions);
  (a.rules || []).forEach(function (rule) {
    var n = (a.counts || {})[rule.id] || 0;
    if (n) fact(box, rule.id + ' ' + rule.name, n);
  });
  fact(box, 'Exceptions', (a.exceptions || []).length);
  fact(box, 'Hash', a.hash);
}
function inventory() {
  if (!deps) return;
  var needle = $('ipath').value;
  var items = deps.filter(function (d) { return has(d.name + ' ' + d.license + ' ' + d.ecosystem, needle); });
  fill($('ilist'), $('icount'), items, function (d) {
    return row([el('span', 'id', d.ecosystem), el('span', 'where', d.name + '  ' + d.version),
      el('span', '', d.license || 'unknown'), el('span', 'dim', d.indirect ? 'indirect' : 'direct')]);
  });
}
function confirmRun(action, question, what) {
  if (!window.confirm(question)) return;
  post('/run', {a: action, confirm: 'yes'}, what).then(function () { report = null; changes = null;
    $('clist').textContent = ''; $('rlist').textContent = ''; }, quiet);
}
document.querySelectorAll('#tabs button').forEach(function (b) { b.onclick = function () { show(b.dataset.tab); }; });
$('scan').onclick = function () { post('/run', {a: 'scan'}, 'Scanning').then(loadReport, quiet); };
$('gate').hidden = !hasGate;
$('update').hidden = !hasUpdate;
$('gate').onclick = function () { post('/run', {a: 'gate'}, 'Checking the gate').then(quiet, quiet); };
$('update').onclick = function () { post('/run', {a: 'update'}, 'Fetching vulnerability data').then(function () { report = null; }, quiet); };
$('frule').onchange = findings;
$('fpath').oninput = findings;
$('preview').onclick = loadChanges;
$('rload').onclick = loadChanges;
$('cpath').oninput = changeList;
$('rpath').oninput = reviewList;
$('apply').onclick = function () { confirmRun('fix',
  'Apply the fix? This changes files on disk. A copy of every changed file is kept for undo.', 'Applying the fix'); };
$('undo').onclick = function () { confirmRun('undo', 'Put back the files from the last fix? Files changed since then are left alone.', 'Undoing'); };
$('lload').onclick = function () { get('readlist', 'Building the reading list').then(readingList, quiet); };
$('aload').onclick = function () { get('audit', 'Building the audit').then(auditView, quiet); };
$('iload').onclick = function () { get('inventory', 'Building the inventory').then(function (inv) { deps = inv.dependencies || []; inventory(); }, quiet); };
$('ipath').oninput = inventory;
['report.html', 'report.sarif', 'report.json', 'audit.json', 'inventory.json', 'bom.json'].forEach(function (name) {
  var a = el('a', '', name);
  a.href = url('/download/' + name);
  $('downloads').append(a);
});
$('open').onclick = function () {
  post('/dir', {dir: $('dir').value, cfg: $('cfg').value}, 'Opening folder').then(function () { window.location.reload(); }, quiet);
};
show('overview');
`
