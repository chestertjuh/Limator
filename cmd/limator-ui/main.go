package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"flag"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
)

type server struct {
	dir, cfg, token, host, work string
	mu                          sync.Mutex
	run                         func(args ...string) (string, error)
}

var page = template.Must(template.New("page").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Limator</title>
<style>
:root{--bg:#0d1416;--panel:#131d20;--line:#1f3a3d;--teal:#0f4c4f;--text:#e6f0f0;--dim:#9fb3b5;--warn:#7a2e22}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 system-ui,sans-serif}
header{padding:16px 24px;border-bottom:1px solid var(--line)}
h1{margin:0;font-size:20px}
.meta{color:var(--dim);word-break:break-all}
.bar{display:flex;flex-wrap:wrap;gap:8px;padding:12px 24px}
button{min-height:44px;padding:8px 16px;background:var(--teal);border:1px solid var(--line);border-radius:6px}
button{color:var(--text);cursor:pointer;font:inherit}
button.danger{background:var(--warn)}
button:disabled{opacity:.5;cursor:wait}
pre{margin:0 24px 12px;padding:12px;background:var(--panel);border:1px solid var(--line);border-radius:8px}
pre{white-space:pre-wrap;word-break:break-word;max-height:40vh;overflow:auto}
iframe{display:block;width:100%;height:80vh;border:0;border-top:1px solid var(--line)}
</style>
</head>
<body>
<header><h1>Limator</h1><div class="meta">{{.Dir}}</div></header>
<div class="bar">
<button id="scan">Scan again</button>
<button id="preview">Preview fix</button>
<button id="fix" class="danger">Apply fix</button>
</div>
<pre id="out" aria-live="polite">Ready.</pre>
<iframe id="report" title="Report" src="/report?t={{.Token}}"></iframe>
<script>
var token = {{.Token}}, out = document.getElementById('out'), buttons = document.querySelectorAll('button');
function busy(on) { buttons.forEach(function (b) { b.disabled = on; }); }
function run(action, question) {
  if (question && !window.confirm(question)) return;
  busy(true);
  out.textContent = 'Running ' + action + '...';
  fetch('/run?t=' + encodeURIComponent(token), {
    method: 'POST',
    headers: {'Content-Type': 'application/x-www-form-urlencoded'},
    body: 'a=' + action + (question ? '&confirm=yes' : '')
  }).then(function (r) { return r.text(); }).then(function (text) {
    out.textContent = text;
    document.getElementById('report').src = '/report?t=' + encodeURIComponent(token) + '&n=' + Date.now();
  }).catch(function (e) { out.textContent = 'Failed: ' + e; }).then(function () { busy(false); });
}
document.getElementById('scan').onclick = function () { run('scan'); };
document.getElementById('preview').onclick = function () { run('preview'); };
document.getElementById('fix').onclick = function () { run('fix', 'Apply the fix? This changes files on disk.'); };
</script>
</body>
</html>
`))

func (s *server) args(cmd string, extra ...string) []string {
	a := []string{cmd, s.dir}
	if s.cfg != "" {
		a = append(a, "-c", s.cfg)
	}
	return append(a, extra...)
}

func (s *server) allowed(w http.ResponseWriter, r *http.Request) bool {
	t := r.URL.Query().Get("t")
	if r.Host != s.host || subtle.ConstantTimeCompare([]byte(t), []byte(s.token)) != 1 {
		http.Error(w, "forbidden", http.StatusForbidden)
		return false
	}
	return true
}

func (s *server) home(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if !s.allowed(w, r) {
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := page.Execute(w, map[string]string{"Dir": s.dir, "Token": s.token}); err != nil {
		fmt.Fprintln(os.Stderr, "limator-ui:", err)
	}
}

func (s *server) report(w http.ResponseWriter, r *http.Request) {
	if !s.allowed(w, r) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	file := filepath.Join(s.work, "report.html")
	if out, err := s.run(s.args("report", "-o", file, "-f", "html")...); err != nil {
		http.Error(w, out+"\n"+err.Error(), http.StatusInternalServerError)
		return
	}
	http.ServeFile(w, r, file)
}

func (s *server) action(w http.ResponseWriter, r *http.Request) {
	if !s.allowed(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "use POST", http.StatusMethodNotAllowed)
		return
	}
	var args []string
	switch r.FormValue("a") {
	case "scan":
		args = s.args("scan")
	case "preview":
		args = s.args("fix", "-n", "yes")
	case "fix":
		if r.FormValue("confirm") != "yes" {
			http.Error(w, "confirmation required", http.StatusBadRequest)
			return
		}
		args = s.args("fix")
	default:
		http.Error(w, "unknown action", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out, err := s.run(args...)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		out += "\n" + err.Error()
	}
	if _, err := w.Write([]byte(out)); err != nil {
		fmt.Fprintln(os.Stderr, "limator-ui:", err)
	}
}

func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.home)
	mux.HandleFunc("/report", s.report)
	mux.HandleFunc("/run", s.action)
	return mux
}

func scanner() string {
	name := "limator"
	if self, err := os.Executable(); err == nil {
		for _, c := range []string{name, name + ".exe"} {
			if p := filepath.Join(filepath.Dir(self), c); fileExists(p) {
				return p
			}
		}
	}
	return name
}

func fileExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && !info.IsDir()
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "limator-ui:", err)
	os.Exit(2)
}

func main() {
	dir := flag.String("dir", "", "folder to scan (required)")
	cfg := flag.String("c", "", "config file")
	port := flag.String("port", "8765", "port on 127.0.0.1")
	bin := flag.String("bin", scanner(), "path of the limator scanner")
	flag.Parse()
	if *dir == "" {
		flag.Usage()
		os.Exit(2)
	}
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		fail(err)
	}
	work, err := os.MkdirTemp("", "limator-ui")
	if err != nil {
		fail(err)
	}
	s := &server{dir: *dir, cfg: *cfg, token: hex.EncodeToString(raw), host: "127.0.0.1:" + *port, work: work}
	s.run = func(args ...string) (string, error) {
		out, err := exec.Command(*bin, args...).CombinedOutput()
		return string(out), err
	}
	ln, err := net.Listen("tcp", s.host)
	if err != nil {
		fail(err)
	}
	fmt.Printf("limator-ui: open http://%s/?t=%s\n", s.host, s.token)
	fail(http.Serve(ln, s.routes()))
}
