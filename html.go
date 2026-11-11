package main

import (
	"bytes"
	"encoding/json"
)

const page = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Limator report</title>
<style>
:root{--bg:#0d1416;--panel:#131d20;--line:#1f3a3d;--teal:#0f4c4f;--text:#e6f0f0;--dim:#9fb3b5;--accent:#5fd4c8}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 system-ui,sans-serif}
header{padding:20px 24px;border-bottom:1px solid var(--line)}
h1{margin:0;font-size:20px}
.meta{color:var(--dim);margin-top:4px;word-break:break-all}
main{display:grid;grid-template-columns:320px 1fr;gap:16px;padding:16px 24px;align-items:start}
@media(max-width:800px){main{grid-template-columns:1fr;padding:12px}}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:8px;overflow:hidden}
.rule{display:flex;gap:8px;width:100%;min-height:44px;align-items:center;padding:8px 12px;text-align:left;cursor:pointer;font:inherit}
.rule{background:none;border:0;border-bottom:1px solid var(--line);color:var(--text)}
.rule:hover,.rule:focus-visible,.rule[aria-pressed=true]{background:var(--teal);outline:none}
.rule .n{margin-left:auto;font-variant-numeric:tabular-nums}
.rule .id{color:var(--accent);font-family:ui-monospace,monospace}
.zero{color:var(--dim)}
.bar{padding:12px;border-bottom:1px solid var(--line)}
input{width:100%;min-height:44px;padding:8px 10px;background:var(--bg);border:1px solid var(--line);border-radius:6px;color:var(--text);font:inherit}
.count{padding:8px 12px;color:var(--dim);border-bottom:1px solid var(--line)}
.row{padding:8px 12px;border-bottom:1px solid var(--line)}
.loc{font-family:ui-monospace,monospace;color:var(--accent);word-break:break-all}
.msg{color:var(--dim);word-break:break-word}
.more{width:100%;min-height:44px;background:var(--teal);border:0;color:var(--text);cursor:pointer;font:inherit}
</style>
</head>
<body>
<header><h1>Limator report</h1><div class="meta" id="meta"></div></header>
<main>
<section class="panel" id="rules" aria-label="Rules"></section>
<section class="panel" aria-label="Findings">
<div class="bar"><input id="q" type="search" placeholder="Filter by file or message" aria-label="Filter by file or message"></div>
<div class="count" id="count" aria-live="polite"></div>
<div id="list"></div>
<button class="more" id="more" hidden>Show more</button>
</section>
</main>
<script id="data" type="application/json">__DATA__</script>
<script>
var rep = JSON.parse(document.getElementById('data').textContent), rule = '', q = '', shown = 200;
function el(tag, cls, text) {
  var e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
}
document.getElementById('meta').textContent = 'version ' + rep.version + ' | ' + rep.files + ' files | ' +
  rep.findings.length + ' findings | hash ' + rep.hash.slice(0, 16);
function button(id, name, count, doc) {
  var b = el('button', 'rule' + (count ? '' : ' zero'));
  if (id) b.append(el('span', 'id', id));
  b.append(el('span', '', name), el('span', 'n', count));
  if (doc) b.title = doc;
  b.setAttribute('aria-pressed', rule === id);
  b.onclick = function () { rule = id; shown = 200; rules(); list(); };
  return b;
}
function rules() {
  var box = document.getElementById('rules');
  box.textContent = '';
  box.append(button('', 'All rules', rep.findings.length, ''));
  rep.rules.forEach(function (r) {
    var n = rep.counts[r.id] || 0, s = (rep.suppressed || {})[r.id] || 0;
    box.append(button(r.id, r.name, s ? n + ' (+' + s + ' excepted)' : n, r.doc));
  });
}
function list() {
  var box = document.getElementById('list'), needle = q.toLowerCase();
  box.textContent = '';
  var hits = rep.findings.filter(function (f) {
    return (!rule || f.rule === rule) && (!needle || (f.file + ' ' + f.msg).toLowerCase().indexOf(needle) >= 0);
  });
  document.getElementById('count').textContent = hits.length + ' matching of ' + rep.findings.length;
  hits.slice(0, shown).forEach(function (f) {
    var row = el('div', 'row');
    row.append(el('div', 'loc', f.rule + '  ' + f.file + ':' + f.line), el('div', 'msg', f.msg));
    box.append(row);
  });
  var more = document.getElementById('more');
  more.hidden = hits.length <= shown;
  more.onclick = function () { shown += 500; list(); };
}
document.getElementById('q').oninput = function (e) { q = e.target.value; shown = 200; list(); };
rules();
list();
</script>
</body>
</html>
`

func htmlReport(rep *Report) ([]byte, error) {
	data, err := json.Marshal(rep)
	if err != nil {
		return nil, err
	}
	return bytes.Replace([]byte(page), []byte("__DATA__"), data, 1), nil
}
