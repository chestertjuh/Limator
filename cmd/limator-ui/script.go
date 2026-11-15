// script.go holds the script of the page.

package main

const script = `
var statusBox = document.getElementById('status'), report = null, changes = null, deps = null, timer = null, shown = 300;
var keptSet = {}, skipped = {}, heads = null;
function $(id) { return document.getElementById(id); }
var nl = {
  'Overview': 'Overzicht', 'Findings': 'Bevindingen', 'Security': 'Beveiliging', 'Fix': 'Herstel', 'Review': 'Nakijken',
  'Reading list': 'Leeslijst', 'Headers': 'Kopregels', 'Audit': 'Audit', 'Inventory': 'Inventaris',
  'Reports and folder': 'Rapporten en map', 'Scan again': 'Opnieuw scannen', 'Check gate': 'Poort controleren',
  'Run the gate on every commit': 'Poort bij elke commit', 'Update vulnerability data': 'Kwetsbaarheidsgegevens bijwerken',
  'Rules': 'Regels', 'All rules': 'Alle regels', 'All levels': 'Alle niveaus', 'high': 'hoog', 'medium': 'midden', 'low': 'laag',
  'Preview fix': 'Voorvertoning', 'Apply fix': 'Herstel toepassen', 'Undo last fix': 'Laatste herstel terugdraaien',
  'Load review list': 'Nakijklijst laden', 'Load reading list': 'Leeslijst laden', 'Load audit': 'Audit laden',
  'Load inventory': 'Inventaris laden', 'Load files without a header': 'Bestanden zonder kopregel laden',
  'Download': 'Downloaden', 'Folder': 'Map', 'Open folder': 'Map openen', 'Show': 'Tonen', 'Code': 'Code',
  'Accept line': 'Regel accepteren', 'Accept file': 'Bestand accepteren', 'Keep as it is': 'Zo laten', 'Skip': 'Overslaan',
  'Mark as read': 'Gelezen', 'Add header': 'Kopregel toevoegen', 'Ready.': 'Klaar.', 'Done.': 'Klaar.',
  'No findings.': 'Geen bevindingen.', 'Nothing left to read.': 'Niets meer te lezen.', 'Nothing here.': 'Niets gevonden.',
  'files': 'bestanden', 'findings': 'bevindingen', 'exceptions': 'uitzonderingen', 'hash': 'hash',
  'Scanning': 'Bezig met scannen', 'Working out the fix': 'Herstel berekenen', 'Applying the fix': 'Herstel toepassen',
  'Undoing': 'Terugdraaien', 'Marking': 'Markeren', 'Recording': 'Vastleggen', 'Adding exception': 'Uitzondering toevoegen',
  'Building the reading list': 'Leeslijst opbouwen', 'Building the audit': 'Audit opbouwen',
  'Building the inventory': 'Inventaris opbouwen', 'Looking for files without a header': 'Bestanden zonder kopregel zoeken',
  'Checking the gate': 'Poort controleren', 'Installing the hook': 'Hook plaatsen', 'Adding the header': 'Kopregel toevoegen',
  'Fetching vulnerability data': 'Kwetsbaarheidsgegevens ophalen', 'Opening folder': 'Map openen',
  'Filter on path or message': 'Filter op pad of melding', 'Filter on path': 'Filter op pad',
  'Filter on name or license': 'Filter op naam of licentie',
  'Preview shows every change before anything is written.\nApply keeps a copy of each file; undo puts those back.':
    'De voorvertoning toont elke wijziging voordat er iets wordt geschreven. Toepassen bewaart een kopie van elk bestand; terugdraaien zet die terug.',
  'Secrets, risky calls and known vulnerabilities, taken from the same scan.':
    'Geheimen, riskante aanroepen en bekende kwetsbaarheden, uit dezelfde scan.',
  'One line at the top of a file saying what it is for. The suggestion is only a start; write your own.':
    'Een regel bovenaan een bestand die zegt waarvoor het is. Het voorstel is een begin; schrijf je eigen tekst.',
  'Apply the fix? This changes files on disk. A copy of every changed file is kept for undo.':
    'Herstel toepassen? Dit wijzigt bestanden op schijf. Van elk gewijzigd bestand blijft een kopie bewaard.',
  'Put back the files from the last fix? Files changed since then are left alone.':
    'De bestanden van het laatste herstel terugzetten? Bestanden die daarna zijn gewijzigd blijven staan.',
  'Write a pre-commit hook in this repository? Every commit then runs the gate.':
    'Een pre-commit-hook in deze repository plaatsen? Elke commit draait dan de poort.'
};
function tr(text) { return lang === 'nl' && typeof text === 'string' && nl[text] ? nl[text] : text; }
function el(tag, cls, text) {
  var e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined && text !== null) e.textContent = tr(text);
  return e;
}
function url(path) { return path + '?t=' + encodeURIComponent(token); }
function busy(on, what) {
  document.querySelectorAll('main button').forEach(function (b) { b.disabled = on; });
  clearInterval(timer);
  $('progress').className = on ? 'on' : '';
  if (!on) return;
  var start = Date.now();
  what = tr(what);
  statusBox.textContent = what + '...';
  timer = setInterval(function () { statusBox.textContent = what + '... ' + Math.round((Date.now() - start) / 1000) + ' s'; }, 1000);
}
var outNl = [
  [/fix: changed (\d+) files, (\d+) comments removed, (\d+) comments cleaned, (\d+) left for review, (\d+) files skipped/,
    'herstel: $1 bestanden gewijzigd, $2 commentaarregels verwijderd, $3 herschreven, $4 om na te kijken, $5 bestanden overgeslagen'],
  [/undo: restored (\d+) files, (\d+) left alone/, 'terugdraaien: $1 bestanden teruggezet, $2 met rust gelaten'],
  [/undo: left (\S+) alone, it changed after the fix/g, 'terugdraaien: $1 is na het herstel gewijzigd en blijft staan'],
  [/gate: ok/, 'poort: in orde'], [/gate: FAIL/g, 'poort: MEER GEWORDEN'], [/gate: better/g, 'poort: minder geworden'],
  [/gate: baseline written to/, 'poort: basislijn geschreven naar'],
  [/hook: every commit now runs the gate against/, 'hook: elke commit draait nu de poort tegen'],
  [/header: added to/, 'kopregel: toegevoegd aan'], [/headers: (\d+) Go files have no leading comment/, 'kopregels: $1 Go-bestanden zonder kopregel'],
  [/exception added for (\S+) in/, 'uitzondering toegevoegd voor $1 in'], [/kept as it is:/, 'zo gelaten:'],
  [/folder set to/, 'map ingesteld op'], [/limator: nothing to undo/, 'limator: er is niets om terug te draaien']
];
function done(text) {
  busy(false);
  text = tr(text);
  if (lang === 'nl') outNl.forEach(function (pair) { text = text.replace(pair[0], pair[1]); });
  statusBox.textContent = text;
}
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
  var some = Math.min(shown, items.length), all = total !== undefined ? total : items.length;
  count.textContent = lang === 'nl' ?
    some + ' van ' + items.length + ' getoond (' + all + ' in totaal). Maak het filter smaller om de rest te zien.' :
    'Showing ' + some + ' of ' + items.length + ' (' + all + ' in total). Narrow the filter to see the rest.';
}
function has(text, needle) { return !needle || text.toLowerCase().indexOf(needle.toLowerCase()) >= 0; }
function exceptButton(rule, file, line) {
  var box = el('span', 'bar');
  [['Accept line', line], ['Accept file', '']].forEach(function (kind) {
    var b = el('button', 'small', kind[0]);
    b.onclick = function () {
      var where = file + (kind[1] ? ':' + kind[1] : '');
      var reason = window.prompt(tr('Why is this acceptable? The reason is stored in the config.') + ' ' + rule + ' ' + where);
      if (reason === null) return;
      post('/except', {rule: rule, path: file, line: kind[1], reason: reason}, 'Adding exception').then(function () { report = null; }, quiet);
    };
    box.append(b);
  });
  return box;
}
function findingRow(f, levels) {
  var r = row([el('span', 'id', f.rule), el('span', 'where', f.file + ':' + f.line), el('span', 'dim', levels[f.rule] || '')]);
  r.append(codeButton(r, f.file, f.line), exceptButton(f.rule, f.file, f.line), el('span', 'code dim', f.msg));
  return r;
}
function security() {
  var levels = report.levels || {}, counts = {}, cards = $('scards');
  var items = (report.findings || []).filter(function (f) { return levels[f.rule] === 'high'; });
  items.forEach(function (f) { counts[f.rule] = (counts[f.rule] || 0) + 1; });
  cards.textContent = '';
  (report.rules || []).forEach(function (rule) { if (counts[rule.id]) cards.append(card(rule.id + ' ' + rule.name, counts[rule.id])); });
  fill($('slist'), $('scount'), items, function (f) { return findingRow(f, levels); });
  if (!items.length) $('slist').append(el('div', 'dim', 'Nothing here.'));
}
function headerList() {
  if (!heads) return;
  var needle = $('hpath').value;
  var items = heads.filter(function (h) { return has(h.file, needle); });
  fill($('hlist'), $('hcount'), items, function (h) {
    var add = el('button', 'small', 'Add header'), r = row([el('span', 'where', h.file), add, el('span', 'code dim', h.suggestion)]);
    add.onclick = function () {
      var text = window.prompt(tr('One line saying what this file is for:') + ' ' + h.file, h.suggestion);
      if (!text) return;
      post('/run', {a: 'header', file: h.file, text: text}, 'Adding the header').then(function () {
        heads = heads.filter(function (x) { return x !== h; });
        report = null;
        r.remove();
      }, quiet);
    };
    return r;
  });
}
function codeButton(r, file, line) {
  var b = el('button', 'small', 'Code');
  b.onclick = function () {
    var old = r.querySelector('pre.ctx');
    if (old) { old.remove(); return; }
    fetch(url('/line') + '&file=' + encodeURIComponent(file) + '&line=' + line).then(function (res) {
      if (!res.ok) throw new Error('the file could not be read');
      return res.json();
    }).then(function (c) {
      var pre = el('pre', 'ctx');
      c.lines.forEach(function (text, i) {
        pre.append(el('span', c.start + i === line ? 'hit' : 'dim', (c.start + i) + '  ' + text + '\n'));
      });
      r.append(pre);
    }, function (e) { statusBox.textContent = 'Failed: ' + e.message; });
  };
  return b;
}
function show(tab) {
  document.querySelectorAll('main section').forEach(function (s) { s.hidden = s.id !== tab; });
  document.querySelectorAll('#tabs button').forEach(function (b) { b.setAttribute('aria-selected', b.dataset.tab === tab); });
  if ((tab === 'overview' || tab === 'findings' || tab === 'security') && !report) loadReport();
}
function loadReport() {
  return get('report', 'Scanning').then(function (data) { report = data; overview(); findings(); security(); }, quiet);
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
    rules.append(row([el('span', 'id', rule.id), el('span', 'where', rule.name),
      el('span', 'dim', (report.levels || {})[rule.id] || ''), el('span', 'num', n), open]));
  });
  if (!total) rules.append(el('div', 'dim', 'No findings.'));
}
function findings() {
  if (!report) return;
  var rule = $('frule').value, needle = $('fpath').value, level = $('flevel').value, levels = report.levels || {};
  var items = (report.findings || []).filter(function (f) {
    return (!rule || f.rule === rule) && (!level || levels[f.rule] === level) && has(f.file + ' ' + f.msg, needle);
  });
  fill($('flist'), $('fcount'), items, function (f) {
    return findingRow(f, levels);
  }, (report.findings || []).length);
}
function loadChanges() {
  return get('changes', 'Working out the fix').then(function (data) {
    changes = data;
    return fetch(url('/kept')).then(function (r) { return r.ok ? r.json() : []; });
  }).then(function (list) {
    keptSet = {};
    list.forEach(function (k) { keptSet[k.file + '\n' + k.text] = true; });
    changeList();
    reviewList();
  }, quiet);
}
function changeList() {
  if (!changes) return;
  var needle = $('cpath').value;
  var items = (changes.changes || []).filter(function (c) { return c.kind !== 'review' && has(c.file, needle); });
  fill($('clist'), $('ccount'), items, function (c) {
    return row([el('span', 'id', c.kind), el('span', 'where', c.file + ':' + c.line),
      el('span', 'code old', c.before), c.after ? el('span', 'code new', c.after) : null]);
  });
  var words = lang === 'nl' ? [' bestanden, ', ' herschreven, ', ' verwijderd, ', ' om na te kijken, ', ' overgeslagen. '] :
    [' files, ', ' rewritten, ', ' removed, ', ' left for review, ', ' skipped. '];
  $('ccount').textContent = changes.files + words[0] + changes.cleaned + words[1] + changes.removed + words[2] +
    changes.review + words[3] + changes.skipped + words[4] + $('ccount').textContent;
}
function reviewList() {
  if (!changes) return;
  var needle = $('rpath').value;
  var items = (changes.changes || []).filter(function (c) {
    return c.kind === 'review' && has(c.file, needle) && !keptSet[c.file + '\n' + c.before] && !skipped[c.file + ':' + c.line];
  });
  fill($('rlist'), $('rcount'), items, function (c) {
    var r = row([el('span', 'where', c.file + ':' + c.line)]);
    var keep = el('button', 'small', 'Keep as it is'), skip = el('button', 'small', 'Skip');
    keep.onclick = function () {
      post('/keep', {file: c.file, text: c.before}, 'Recording').then(function () {
        keptSet[c.file + '\n' + c.before] = true;
        r.remove();
      }, quiet);
    };
    skip.onclick = function () { skipped[c.file + ':' + c.line] = true; r.remove(); };
    r.append(codeButton(r, c.file, c.line), keep, skip, exceptButton('L001', c.file, c.line), el('span', 'code', c.before));
    return r;
  });
}
function readingList(units) {
  var box = $('llist');
  box.textContent = '';
  if (!units.length) box.append(el('div', 'dim', 'Nothing left to read.'));
  units.forEach(function (u) {
    var mark = el('button', 'small', 'Mark as read');
    var r = row([el('span', 'id', u.score), el('span', 'where', u.file + ':' + u.line + '  ' + u.func),
      el('span', 'dim', (u.sensitive || []).join(' ') + '  complexity ' + u.complexity + ', findings ' + u.findings + ', changes ' + (u.churn || 0)), mark]);
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
  if (!window.confirm(tr(question))) return;
  post('/run', {a: action, confirm: 'yes'}, what).then(function () { report = null; changes = null;
    $('clist').textContent = ''; $('rlist').textContent = ''; }, quiet);
}
document.querySelectorAll('#tabs button').forEach(function (b) { b.onclick = function () { show(b.dataset.tab); }; });
$('scan').onclick = function () { post('/run', {a: 'scan'}, 'Scanning').then(loadReport, quiet); };
$('update').hidden = !hasUpdate;
$('gate').onclick = function () { post('/run', {a: 'gate'}, 'Checking the gate').then(quiet, quiet); };
$('update').onclick = function () { post('/run', {a: 'update'}, 'Fetching vulnerability data').then(function () { report = null; }, quiet); };
$('frule').onchange = findings;
$('flevel').onchange = findings;
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
$('hook').onclick = function () {
  confirmRun('hook', 'Write a pre-commit hook in this repository? Every commit then runs the gate.', 'Installing the hook');
};
$('hload').onclick = function () {
  get('headers', 'Looking for files without a header').then(function (list) { heads = list; headerList(); }, quiet);
};
$('hpath').oninput = headerList;
if (lang === 'nl') {
  document.querySelectorAll('button, h2, option, main .dim, #status').forEach(function (e) {
    if (!e.children.length && nl[e.textContent]) e.textContent = nl[e.textContent];
  });
  document.querySelectorAll('input[placeholder]').forEach(function (e) { e.placeholder = tr(e.placeholder); });
}
show('overview');
`
