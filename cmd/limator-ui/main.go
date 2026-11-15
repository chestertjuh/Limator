package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

type server struct {
	mu                         sync.Mutex
	dir, cfg, who, base, vulns string
	token, host, work          string
	bin, updater               string
	fresh                      map[string]bool
	run                        func(bin string, args ...string) (string, error)
}

type exception struct {
	Rule   string `json:"rule"`
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

var (
	ruleID = regexp.MustCompile(`^[A-Z]+[0-9]+$`)

	documents = map[string][]string{
		"report":    {"report", "-f", "json"},
		"changes":   {"fix", "-n", "yes"},
		"readlist":  {"readlist", "-n", "200"},
		"audit":     {"audit"},
		"inventory": {"inventory"},
	}

	downloads = map[string][]string{
		"report.html":    {"report", "-f", "html"},
		"report.sarif":   {"report", "-f", "sarif"},
		"report.json":    {"report", "-f", "json"},
		"audit.json":     {"audit"},
		"inventory.json": {"inventory"},
		"bom.json":       {"inventory", "-f", "cyclonedx"},
	}
)

func (s *server) args(cmd string, extra ...string) []string {
	a := []string{cmd, s.dir}
	if s.cfg != "" {
		a = append(a, "-c", s.cfg)
	}
	return append(a, extra...)
}

func (s *server) configPath() string {
	if s.cfg != "" {
		return s.cfg
	}
	return filepath.Join(s.dir, "limator.json")
}

func (s *server) allowed(w http.ResponseWriter, r *http.Request) bool {
	t := r.URL.Query().Get("t")
	if r.Host != s.host || subtle.ConstantTimeCompare([]byte(t), []byte(s.token)) != 1 {
		http.Error(w, "forbidden", http.StatusForbidden)
		return false
	}
	if origin := r.Header.Get("Origin"); origin != "" && origin != "http://"+s.host {
		http.Error(w, "forbidden", http.StatusForbidden)
		return false
	}
	h := w.Header()
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Cache-Control", "no-store")
	return true
}

func (s *server) posted(w http.ResponseWriter, r *http.Request) bool {
	if !s.allowed(w, r) {
		return false
	}
	if r.Method != http.MethodPost {
		http.Error(w, "use POST", http.StatusMethodNotAllowed)
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	return true
}

func plain(v string) bool {
	return v != "" && !strings.HasPrefix(v, "-")
}

func reply(w http.ResponseWriter, out string, err error) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		out += "\n" + err.Error()
	}
	if _, err := w.Write([]byte(out)); err != nil {
		fmt.Fprintln(os.Stderr, "limator-ui:", err)
	}
}

func (s *server) home(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if !s.allowed(w, r) {
		return
	}
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		http.Error(w, "no random source", http.StatusInternalServerError)
		return
	}
	nonce := hex.EncodeToString(raw)
	w.Header().Set("Content-Security-Policy", "default-src 'none'; connect-src 'self'; style-src 'nonce-"+nonce+"'; "+
		"script-src 'nonce-"+nonce+"'; base-uri 'none'; form-action 'none'")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	s.mu.Lock()
	data := map[string]any{"Dir": s.dir, "Cfg": s.configPath(), "Token": s.token, "Nonce": nonce,
		"Who": s.who, "Gate": s.base != "", "Update": s.vulns != "" && s.updater != ""}
	s.mu.Unlock()
	if err := page.Execute(w, data); err != nil {
		fmt.Fprintln(os.Stderr, "limator-ui:", err)
	}
}

func (s *server) produce(name string, cmd []string) (string, string, error) {
	file := filepath.Join(s.work, name)
	if s.fresh[name] {
		return file, "", nil
	}
	out, err := s.run(s.bin, s.args(cmd[0], append(append([]string{}, cmd[1:]...), "-o", file)...)...)
	if err == nil {
		s.fresh[name] = true
	}
	return file, out, err
}

func (s *server) data(w http.ResponseWriter, r *http.Request) {
	if !s.allowed(w, r) {
		return
	}
	name := strings.TrimPrefix(r.URL.Path, "/data/")
	cmd, ok := documents[name]
	if !ok {
		http.NotFound(w, r)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	file, out, err := s.produce(name+".json", cmd)
	if err != nil {
		http.Error(w, out+"\n"+err.Error(), http.StatusInternalServerError)
		return
	}
	http.ServeFile(w, r, file)
}

func (s *server) download(w http.ResponseWriter, r *http.Request) {
	if !s.allowed(w, r) {
		return
	}
	name := strings.TrimPrefix(r.URL.Path, "/download/")
	cmd, ok := downloads[name]
	if !ok {
		http.NotFound(w, r)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	file, out, err := s.produce("download-"+name, cmd)
	if err != nil {
		http.Error(w, out+"\n"+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Disposition", `attachment; filename="limator-`+name+`"`)
	http.ServeFile(w, r, file)
}

func (s *server) action(w http.ResponseWriter, r *http.Request) {
	if !s.posted(w, r) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fresh = map[string]bool{}
	bin := s.bin
	var args []string
	switch r.FormValue("a") {
	case "scan":
		args = s.args("scan")
	case "fix", "undo":
		if r.FormValue("confirm") != "yes" {
			http.Error(w, "confirmation required", http.StatusBadRequest)
			return
		}
		args = s.args(r.FormValue("a"))
	case "read":
		file, fn := r.FormValue("file"), r.FormValue("fn")
		if !plain(file) || !plain(fn) || !plain(s.who) {
			http.Error(w, "file, function and a -who name are required", http.StatusBadRequest)
			return
		}
		args = s.args("read", "-who", s.who, "-f", file, "-fn", fn)
	case "gate":
		if s.base == "" {
			http.Error(w, "start limator-ui with -b baseline.json", http.StatusBadRequest)
			return
		}
		args = s.args("gate", "-b", s.base)
	case "update":
		if s.vulns == "" || s.updater == "" {
			http.Error(w, "start limator-ui with -vulndb folder", http.StatusBadRequest)
			return
		}
		bin, args = s.updater, []string{"vulndb", "-dir", s.vulns}
	default:
		http.Error(w, "unknown action", http.StatusBadRequest)
		return
	}
	out, err := s.run(bin, args...)
	reply(w, out, err)
}

func (s *server) except(w http.ResponseWriter, r *http.Request) {
	if !s.posted(w, r) {
		return
	}
	e := exception{r.FormValue("rule"), r.FormValue("path"), strings.TrimSpace(r.FormValue("reason"))}
	if !ruleID.MatchString(e.Rule) || !plain(e.Path) || len(e.Reason) < 10 {
		http.Error(w, "a rule, a path and a reason of at least 10 characters are required", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fresh = map[string]bool{}
	reply(w, "exception added for "+e.Rule+" in "+e.Path, addException(s.configPath(), e))
}

func addException(file string, e exception) error {
	doc := map[string]json.RawMessage{}
	raw, err := os.ReadFile(file)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err == nil {
		if err := json.Unmarshal(raw, &doc); err != nil {
			return fmt.Errorf("config does not parse: %v", err)
		}
	}
	var list []json.RawMessage
	if cur, ok := doc["exceptions"]; ok {
		if err := json.Unmarshal(cur, &list); err != nil {
			return fmt.Errorf("exceptions in the config do not parse: %v", err)
		}
	}
	item, err := json.Marshal(e)
	if err != nil {
		return err
	}
	if doc["exceptions"], err = json.Marshal(append(list, item)); err != nil {
		return err
	}
	next, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	tmp := file + ".limator-tmp"
	if err := os.WriteFile(tmp, append(next, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, file)
}

func (s *server) folder(w http.ResponseWriter, r *http.Request) {
	if !s.posted(w, r) {
		return
	}
	dir, cfg := r.FormValue("dir"), r.FormValue("cfg")
	info, err := os.Stat(dir)
	if !plain(dir) || !filepath.IsAbs(dir) || err != nil || !info.IsDir() {
		http.Error(w, "give the full path of an existing folder", http.StatusBadRequest)
		return
	}
	if cfg != "" && (!plain(cfg) || !filepath.IsAbs(cfg) || !fileExists(cfg)) {
		http.Error(w, "give the full path of an existing config file, or leave it empty", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	s.dir, s.cfg, s.fresh = filepath.Clean(dir), cfg, map[string]bool{}
	s.mu.Unlock()
	reply(w, "folder set to "+dir, nil)
}

func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.home)
	mux.HandleFunc("/data/", s.data)
	mux.HandleFunc("/download/", s.download)
	mux.HandleFunc("/run", s.action)
	mux.HandleFunc("/except", s.except)
	mux.HandleFunc("/dir", s.folder)
	return mux
}

func beside(name string) string {
	if self, err := os.Executable(); err == nil {
		for _, c := range []string{name, name + ".exe"} {
			if p := filepath.Join(filepath.Dir(self), c); fileExists(p) {
				return p
			}
		}
	}
	return ""
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
	scanner := beside("limator")
	if scanner == "" {
		scanner = "limator"
	}
	dir := flag.String("dir", "", "folder to scan (required, full path)")
	cfg := flag.String("c", "", "config file")
	port := flag.String("port", "8765", "port on 127.0.0.1")
	who := flag.String("who", "", "name recorded when you mark a function as read")
	base := flag.String("b", "", "baseline file for the gate")
	vulns := flag.String("vulndb", "", "folder for the vulnerability data; enables the update button")
	bin := flag.String("bin", scanner, "path of the limator scanner")
	flag.Parse()
	abs, err := filepath.Abs(*dir)
	if *dir == "" || err != nil {
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
	s := &server{dir: abs, cfg: *cfg, who: *who, base: *base, vulns: *vulns, token: hex.EncodeToString(raw),
		host: "127.0.0.1:" + *port, work: work, bin: *bin, fresh: map[string]bool{}, updater: beside("limator-update")}
	s.run = func(bin string, args ...string) (string, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
		defer cancel()
		out, err := exec.CommandContext(ctx, bin, args...).CombinedOutput()
		return string(out), err
	}
	ln, err := net.Listen("tcp", s.host)
	if err != nil {
		fail(err)
	}
	fmt.Printf("limator-ui: open http://%s/?t=%s\n", s.host, s.token)
	srv := &http.Server{Handler: s.routes(), ReadHeaderTimeout: 10 * time.Second}
	fail(srv.Serve(ln))
}
