package main

import "html/template"

var page = template.Must(template.New("page").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Limator</title>
<style nonce="{{.Nonce}}">
:root{--bg:#0d1416;--panel:#131d20;--line:#1f3a3d;--teal:#0f4c4f;--text:#e6f0f0;--dim:#9fb3b5;--accent:#5fd4c8;--warn:#7a2e22;--ok:#1f5a3a}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 system-ui,sans-serif}
header{padding:16px 24px 8px;border-bottom:1px solid var(--line)}
h1{margin:0;font-size:20px}
h2{margin:16px 0 8px;font-size:16px}
.meta,.dim{color:var(--dim)}
.meta{word-break:break-all}
nav{display:flex;flex-wrap:wrap;gap:4px;padding:8px 24px;border-bottom:1px solid var(--line);position:sticky;top:0;background:var(--bg)}
button,select,input{min-height:44px;padding:8px 12px;border:1px solid var(--line);border-radius:6px;font:inherit;color:var(--text)}
button{background:var(--teal);cursor:pointer}
button:focus-visible,input:focus-visible,select:focus-visible,a:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
nav button{background:transparent}
nav button[aria-selected=true]{background:var(--teal);border-color:var(--accent)}
button.danger{background:var(--warn)}
button.small{min-height:36px;padding:4px 10px}
button:disabled{opacity:.5;cursor:wait}
input,select{background:var(--panel)}
input.wide{flex:1;min-width:220px}
main{padding:12px 24px 48px}
#status{margin:12px 24px 0;padding:8px 12px;background:var(--panel);border:1px solid var(--line);border-radius:8px;
white-space:pre-wrap;word-break:break-word;max-height:30vh;overflow:auto}
.bar{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin:8px 0}
.cards{display:flex;flex-wrap:wrap;gap:12px;margin:8px 0}
.card{min-width:140px;padding:12px;background:var(--panel);border:1px solid var(--line);border-radius:8px}
.card b{display:block;font-size:22px;font-variant-numeric:tabular-nums;color:var(--accent)}
.row{display:flex;flex-wrap:wrap;gap:8px;align-items:center;padding:8px 0;border-bottom:1px solid var(--line)}
.id{min-width:64px;font-variant-numeric:tabular-nums;color:var(--accent)}
.num{min-width:64px;text-align:right;font-variant-numeric:tabular-nums}
.where{flex:1;min-width:220px;word-break:break-all}
.code{flex-basis:100%;font:13px/1.4 ui-monospace,Consolas,monospace;white-space:pre-wrap;word-break:break-word}
.old{color:#e0a59b}
.new{color:#9be0b4}
a{color:var(--accent)}
section[hidden]{display:none}
</style>
</head>
<body>
<header><h1>Limator</h1><div class="meta" id="where">{{.Dir}}</div><div class="meta">config: {{.Cfg}}</div></header>
<nav role="tablist" id="tabs">
<button role="tab" data-tab="overview">Overview</button>
<button role="tab" data-tab="findings">Findings</button>
<button role="tab" data-tab="fix">Fix</button>
<button role="tab" data-tab="review">Review</button>
<button role="tab" data-tab="reading">Reading list</button>
<button role="tab" data-tab="audit">Audit</button>
<button role="tab" data-tab="inventory">Inventory</button>
<button role="tab" data-tab="files">Reports and folder</button>
</nav>
<div id="status" aria-live="polite">Ready.</div>
<main>
<section id="overview">
<div class="bar"><button id="scan">Scan again</button><button id="gate">Check gate</button><button id="update">Update vulnerability data</button></div>
<div class="cards" id="cards"></div>
<h2>Rules</h2><div id="rules"></div>
</section>
<section id="findings" hidden>
<div class="bar"><select id="frule" aria-label="Rule"></select><input class="wide" id="fpath" placeholder="Filter on path or message" aria-label="Filter"></div>
<div class="dim" id="fcount"></div><div id="flist"></div>
</section>
<section id="fix" hidden>
<div class="bar"><button id="preview">Preview fix</button><button id="apply" class="danger">Apply fix</button>
<button id="undo" class="danger">Undo last fix</button>
<input class="wide" id="cpath" placeholder="Filter on path" aria-label="Filter"></div>
<div class="dim" id="ccount">Preview shows every change before anything is written.
Apply keeps a copy of each file; undo puts those back.</div><div id="clist"></div>
</section>
<section id="review" hidden>
<div class="bar"><button id="rload">Load review list</button><input class="wide" id="rpath" placeholder="Filter on path" aria-label="Filter"></div>
<div class="dim" id="rcount">Matches the fix leaves alone because removing them would break a sentence.
Rewrite them by hand, or record an exception with a reason.</div><div id="rlist"></div>
</section>
<section id="reading" hidden>
<div class="bar"><button id="lload">Load reading list</button>
<span class="dim">Marks are recorded as: {{if .Who}}{{.Who}}{{else}}nobody, start with -who name{{end}}</span></div><div id="llist"></div>
</section>
<section id="audit" hidden><div class="bar"><button id="aload">Load audit</button></div><div id="alist"></div></section>
<section id="inventory" hidden>
<div class="bar"><button id="iload">Load inventory</button><input class="wide" id="ipath" placeholder="Filter on name or license" aria-label="Filter"></div>
<div class="dim" id="icount"></div><div id="ilist"></div>
</section>
<section id="files" hidden>
<h2>Download</h2>
<div class="bar" id="downloads"></div>
<h2>Folder</h2>
<div class="bar"><input class="wide" id="dir" value="{{.Dir}}" aria-label="Folder, full path">
<input class="wide" id="cfg" placeholder="Config file, empty for limator.json in the folder" aria-label="Config file">
<button id="open">Open folder</button></div>
</section>
</main>
<script nonce="{{.Nonce}}">
var token = {{.Token}}, hasGate = {{.Gate}}, hasUpdate = {{.Update}};
</script>
<script nonce="{{.Nonce}}">` + script + `</script>
</body>
</html>
`))
