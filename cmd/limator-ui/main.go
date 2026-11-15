// main.go is the local web server that drives the scanner from a browser.

package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
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
	"strconv"
	"strings"
	"sync"
	"time"
)

type server struct {
	mu                         sync.Mutex
	dir, cfg, who, base, vulns string
	token, host, work, store   string
	lang                       string
	bin, updater               string
	fresh                      map[string]bool
	run                        func(bin string, args ...string) (string, error)
}

type exception struct {
	Rule   string `json:"rule"`
	Path   string `json:"path"`
	Reason string `json:"reason"`
	Line   string `json:"line,omitempty"`
}

var (
	ruleID = regexp.MustCompile(`^[A-Z]+[0-9]+$`)

	documents = map[string][]string{
		"report":    {"report", "-f", "json"},
		"changes":   {"fix", "-n", "yes"},
		"readlist":  {"readlist", "-n", "200"},
		"audit":     {"audit"},
		"inventory": {"inventory"},
		"headers":   {"headers"},
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
		"Who": s.who, "Update": s.updater != "", "Lang": s.lang}
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
	after := func() error { return nil }
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
		args = s.args("gate", "-b", s.basePath())
	case "hook":
		if r.FormValue("confirm") != "yes" {
			http.Error(w, "confirmation required", http.StatusBadRequest)
			return
		}
		args = s.args("hook", "-b", s.basePath())
	case "header":
		file, text := r.FormValue("file"), strings.TrimSpace(r.FormValue("text"))
		if !plain(file) || !plain(text) {
			http.Error(w, "file and text required", http.StatusBadRequest)
			return
		}
		args = []string{"header", s.dir, "-f", file, "-text", text}
	case "update":
		if s.updater == "" {
			http.Error(w, "limator-update was not found beside limator-ui", http.StatusBadRequest)
			return
		}
		dir := s.vulnDir()
		if dir == "" {
			dir = filepath.Join(s.store, "vulndb")
			after = func() error {
				return editConfig(s.configPath(), func(doc map[string]json.RawMessage) error {
					raw, err := json.Marshal(dir)
					doc["vuln_db"] = raw
					return err
				})
			}
		}
		bin, args = s.updater, []string{"vulndb", "-dir", dir}
	default:
		http.Error(w, "unknown action", http.StatusBadRequest)
		return
	}
	out, err := s.run(bin, args...)
	if err == nil {
		err = after()
	}
	reply(w, out, err)
}

func (s *server) except(w http.ResponseWriter, r *http.Request) {
	if !s.posted(w, r) {
		return
	}
	e := exception{Rule: r.FormValue("rule"), Path: r.FormValue("path"), Reason: strings.TrimSpace(r.FormValue("reason"))}
	if !ruleID.MatchString(e.Rule) || !plain(e.Path) || len(e.Reason) < 10 {
		http.Error(w, "a rule, a path and a reason of at least 10 characters are required", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if n := r.FormValue("line"); n != "" {
		lines, at, err := s.source(e.Path, n)
		if err != nil || strings.TrimSpace(lines[at]) == "" {
			http.Error(w, "that line could not be read", http.StatusBadRequest)
			return
		}
		e.Line = strings.TrimSpace(lines[at])
	}
	s.fresh = map[string]bool{}
	reply(w, "exception added for "+e.Rule+" in "+e.Path, addException(s.configPath(), e))
}

func addException(file string, e exception) error {
	return editConfig(file, func(doc map[string]json.RawMessage) error {
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
		doc["exceptions"], err = json.Marshal(append(list, item))
		return err
	})
}

func editConfig(file string, change func(doc map[string]json.RawMessage) error) error {
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
	if err := change(doc); err != nil {
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
	if err := os.Rename(tmp, file); err != nil {
		if gone := os.Remove(tmp); gone != nil {
			return fmt.Errorf("%w; the temporary file %s is still there", err, tmp)
		}
		return err
	}
	return nil
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
	mux.HandleFunc("/line", s.line)
	mux.HandleFunc("/keep", s.keep)
	mux.HandleFunc("/kept", s.keptList)
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
	base := flag.String("b", "", "baseline file for the gate; default limator-baseline.json beside the config")
	lang := flag.String("lang", "en", "language of the page: en or nl")
	vulns := flag.String("vulndb", "", "folder for the vulnerability data; default the vuln_db of the config")
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
	home, err := os.UserCacheDir()
	if err != nil {
		fail(err)
	}
	store := filepath.Join(home, "limator")
	s := &server{dir: abs, cfg: *cfg, who: *who, base: *base, vulns: *vulns, token: hex.EncodeToString(raw),
		host: "127.0.0.1:" + *port, work: work, store: store, lang: *lang, bin: *bin, fresh: map[string]bool{}, updater: beside("limator-update")}
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

type kept struct {
	File string `json:"file"`
	Text string `json:"text"`
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		fmt.Fprintln(os.Stderr, "limator-ui:", err)
	}
}

func (s *server) keptPath() string {
	sum := sha256.Sum256([]byte(s.dir))
	return filepath.Join(s.store, "review-"+hex.EncodeToString(sum[:8])+".json")
}

func (s *server) readKept() ([]kept, error) {
	list := []kept{}
	raw, err := os.ReadFile(s.keptPath())
	if os.IsNotExist(err) {
		return list, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil, err
	}
	return list, nil
}

func (s *server) keptList(w http.ResponseWriter, r *http.Request) {
	if !s.allowed(w, r) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	list, err := s.readKept()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, list)
}

func (s *server) keep(w http.ResponseWriter, r *http.Request) {
	if !s.posted(w, r) {
		return
	}
	item := kept{r.FormValue("file"), r.FormValue("text")}
	if !plain(item.File) || item.Text == "" {
		http.Error(w, "file and text required", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	list, err := s.readKept()
	if err != nil {
		reply(w, "", err)
		return
	}
	raw, err := json.MarshalIndent(append(list, item), "", "  ")
	if err == nil {
		if err = os.MkdirAll(s.store, 0o700); err == nil {
			err = os.WriteFile(s.keptPath(), raw, 0o600)
		}
	}
	reply(w, "kept as it is: "+item.File, err)
}

func (s *server) line(w http.ResponseWriter, r *http.Request) {
	if !s.allowed(w, r) {
		return
	}
	s.mu.Lock()
	lines, at, err := s.source(r.URL.Query().Get("file"), r.URL.Query().Get("line"))
	s.mu.Unlock()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	from, to := max(at-2, 0), min(at+3, len(lines))
	writeJSON(w, map[string]any{"start": from + 1, "lines": lines[from:to]})
}

func (s *server) source(file, line string) ([]string, int, error) {
	file = filepath.FromSlash(file)
	n, err := strconv.Atoi(line)
	if err != nil || n < 1 || !filepath.IsLocal(file) {
		return nil, 0, fmt.Errorf("file and line required")
	}
	raw, err := os.ReadFile(filepath.Join(s.dir, file))
	if err != nil {
		return nil, 0, fmt.Errorf("file not found")
	}
	lines := strings.Split(strings.ReplaceAll(string(raw), "\r", ""), "\n")
	if n > len(lines) {
		return nil, 0, fmt.Errorf("the file has no line %d", n)
	}
	return lines, n - 1, nil
}

func (s *server) basePath() string {
	if s.base != "" {
		return s.base
	}
	return filepath.Join(filepath.Dir(s.configPath()), "limator-baseline.json")
}

func (s *server) vulnDir() string {
	if s.vulns != "" {
		return s.vulns
	}
	raw, err := os.ReadFile(s.configPath())
	if err != nil {
		return ""
	}
	var doc struct {
		VulnDB string `json:"vuln_db"`
	}
	if json.Unmarshal(raw, &doc) != nil || doc.VulnDB == "" {
		return ""
	}
	if filepath.IsAbs(doc.VulnDB) {
		return doc.VulnDB
	}
	return filepath.Join(filepath.Dir(s.configPath()), doc.VulnDB)
}
