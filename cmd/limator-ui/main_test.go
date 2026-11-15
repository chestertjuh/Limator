package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testServer(t *testing.T) (*server, *[][]string) {
	t.Helper()
	var calls [][]string
	s := &server{dir: t.TempDir(), who: "tester", token: "secret", host: "127.0.0.1:8765",
		work: t.TempDir(), store: t.TempDir(), bin: "limator", fresh: map[string]bool{}}
	s.run = func(bin string, args ...string) (string, error) {
		calls = append(calls, append([]string{bin}, args...))
		for i, a := range args {
			if a == "-o" {
				if err := os.WriteFile(args[i+1], []byte(`{"ok":true}`), 0o600); err != nil {
					return "", err
				}
			}
		}
		return "ran " + args[0], nil
	}
	return s, &calls
}

func do(s *server, method, target, body string, origin string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "http://127.0.0.1:8765"+target, strings.NewReader(body))
	if body != "" {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	w := httptest.NewRecorder()
	s.routes().ServeHTTP(w, r)
	return w
}

func TestAccessNeedsTokenLocalHostAndOwnOrigin(t *testing.T) {
	s, _ := testServer(t)
	if w := do(s, "GET", "/", "", ""); w.Code != http.StatusForbidden {
		t.Fatalf("no token: %d", w.Code)
	}
	if w := do(s, "POST", "/run?t=secret", "a=scan", "http://evil.example"); w.Code != http.StatusForbidden {
		t.Fatalf("foreign origin: %d", w.Code)
	}
	r := httptest.NewRequest("GET", "http://evil.example/?t=secret", nil)
	w := httptest.NewRecorder()
	s.routes().ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("wrong host: %d", w.Code)
	}
	w = do(s, "GET", "/?t=secret", "", "")
	if w.Code != http.StatusOK || !strings.Contains(w.Header().Get("Content-Security-Policy"), "default-src 'none'") {
		t.Fatalf("home: %d %q", w.Code, w.Header().Get("Content-Security-Policy"))
	}
}

func TestActions(t *testing.T) {
	s, calls := testServer(t)
	if w := do(s, "POST", "/run?t=secret", "a=fix", ""); w.Code != http.StatusBadRequest {
		t.Fatalf("fix without confirm: %d", w.Code)
	}
	if w := do(s, "POST", "/run?t=secret", "a=undo", ""); w.Code != http.StatusBadRequest {
		t.Fatalf("undo without confirm: %d", w.Code)
	}
	if w := do(s, "POST", "/run?t=secret", "a=read&file=-x&fn=F", ""); w.Code != http.StatusBadRequest {
		t.Fatalf("flag as file: %d", w.Code)
	}
	if w := do(s, "POST", "/run?t=secret", "a=hook", ""); w.Code != http.StatusBadRequest {
		t.Fatalf("hook without confirm: %d", w.Code)
	}
	if w := do(s, "GET", "/run?t=secret&a=scan", "", ""); w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("get: %d", w.Code)
	}
	if len(*calls) != 0 {
		t.Fatalf("refused requests ran the scanner: %v", *calls)
	}
	if w := do(s, "POST", "/run?t=secret", "a=undo&confirm=yes", ""); w.Code != http.StatusOK || (*calls)[0][1] != "undo" {
		t.Fatalf("undo: %d %v", w.Code, *calls)
	}
}

func TestDataAndDownloads(t *testing.T) {
	s, calls := testServer(t)
	if w := do(s, "GET", "/data/changes?t=secret", "", ""); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "ok") {
		t.Fatalf("changes: %d %s", w.Code, w.Body)
	}
	if got := strings.Join((*calls)[0][1:], " "); !strings.HasPrefix(got, "fix "+s.dir+" -n yes -o ") {
		t.Fatalf("preview must not write: %s", got)
	}
	if w := do(s, "GET", "/download/bom.json?t=secret", "", ""); w.Code != http.StatusOK ||
		!strings.Contains(w.Header().Get("Content-Disposition"), "attachment") {
		t.Fatalf("download: %d", w.Code)
	}
	if w := do(s, "GET", "/data/../main.go?t=secret", "", ""); w.Code == http.StatusOK {
		t.Fatalf("unknown document served")
	}
}

func TestExceptionNeedsReasonAndIsStored(t *testing.T) {
	s, _ := testServer(t)
	cfg := filepath.Join(s.dir, "limator.json")
	if err := os.WriteFile(cfg, []byte(`{"max_line_length":120,"exceptions":[{"rule":"L001","path":"a.go","reason":"kept on purpose"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if w := do(s, "POST", "/except?t=secret", "rule=L004&path=b.go&reason=short", ""); w.Code != http.StatusBadRequest {
		t.Fatalf("short reason: %d", w.Code)
	}
	if w := do(s, "POST", "/except?t=secret", "rule=L004&path=b.go&reason=the+error+is+logged+one+line+up", ""); w.Code != http.StatusOK {
		t.Fatalf("add: %d %s", w.Code, w.Body)
	}
	got, err := os.ReadFile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"max_line_length": 120`, "kept on purpose",
		`"rule": "L004"`, "logged one line up"} {
		if !strings.Contains(string(got), want) {
			t.Fatalf("missing %s in:\n%s", want, got)
		}
	}
}

func TestFolderMustExist(t *testing.T) {
	s, _ := testServer(t)
	old := s.dir
	if w := do(s, "POST", "/dir?t=secret", "dir="+filepath.ToSlash(filepath.Join(old, "missing")), ""); w.Code != http.StatusBadRequest {
		t.Fatalf("missing folder: %d", w.Code)
	}
	next := t.TempDir()
	if w := do(s, "POST", "/dir?t=secret", "dir="+filepath.ToSlash(next), ""); w.Code != http.StatusOK || s.dir != filepath.Clean(next) {
		t.Fatalf("switch: %d %s", w.Code, s.dir)
	}
}

func TestDocumentsAreReusedUntilSomethingChanges(t *testing.T) {
	s, calls := testServer(t)
	for i := 0; i < 2; i++ {
		if w := do(s, "GET", "/data/audit?t=secret", "", ""); w.Code != http.StatusOK {
			t.Fatalf("audit: %d", w.Code)
		}
	}
	if len(*calls) != 1 {
		t.Fatalf("second request ran the scanner again: %v", *calls)
	}
	if w := do(s, "POST", "/run?t=secret", "a=scan", ""); w.Code != http.StatusOK {
		t.Fatalf("scan: %d", w.Code)
	}
	if w := do(s, "GET", "/data/audit?t=secret", "", ""); w.Code != http.StatusOK || len(*calls) != 3 {
		t.Fatalf("after a scan the document must be rebuilt: %d %v", w.Code, *calls)
	}
}

func TestLineShowsContextAndStaysInsideTheFolder(t *testing.T) {
	s, _ := testServer(t)
	if err := os.WriteFile(filepath.Join(s.dir, "a.go"), []byte("one\ntwo\nthree\nfour\nfive\nsix\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	w := do(s, "GET", "/line?t=secret&file=a.go&line=4", "", "")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"start":2`) || !strings.Contains(w.Body.String(), `"two","three","four","five"`) {
		t.Fatalf("line: %d %s", w.Code, w.Body)
	}
	if w := do(s, "GET", "/line?t=secret&file=../secret.txt&line=1", "", ""); w.Code != http.StatusBadRequest {
		t.Fatalf("path outside the folder: %d", w.Code)
	}
}

func TestKeptLinesAreRemembered(t *testing.T) {
	s, _ := testServer(t)
	if w := do(s, "POST", "/keep?t=secret", "file=a.go&text=", ""); w.Code != http.StatusBadRequest {
		t.Fatalf("empty text: %d", w.Code)
	}
	if w := do(s, "POST", "/keep?t=secret", "file=a.go&text=%2F%2F+kept+line", ""); w.Code != http.StatusOK {
		t.Fatalf("keep: %d %s", w.Code, w.Body)
	}
	if w := do(s, "GET", "/kept?t=secret", "", ""); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "// kept line") {
		t.Fatalf("kept: %d %s", w.Code, w.Body)
	}
}

func TestLineExceptionStoresTheSourceLine(t *testing.T) {
	s, _ := testServer(t)
	if err := os.WriteFile(filepath.Join(s.dir, "a.go"), []byte("package p\n\n\t// kept on this line\nvar A = 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if w := do(s, "POST", "/except?t=secret", "rule=L001&path=a.go&line=3&reason=this+one+explains+the+code", ""); w.Code != http.StatusOK {
		t.Fatalf("add: %d %s", w.Code, w.Body)
	}
	got, err := os.ReadFile(filepath.Join(s.dir, "limator.json"))
	if err != nil || !strings.Contains(string(got), `"line": "// kept on this line"`) {
		t.Fatalf("%v config:\n%s", err, got)
	}
	if w := do(s, "POST", "/except?t=secret", "rule=L001&path=a.go&line=99&reason=this+one+explains+the+code", ""); w.Code != http.StatusBadRequest {
		t.Fatalf("missing line: %d", w.Code)
	}
}

func TestGateUsesADefaultBaselineAndHeaderNeedsText(t *testing.T) {
	s, calls := testServer(t)
	if w := do(s, "POST", "/run?t=secret", "a=gate", ""); w.Code != http.StatusOK {
		t.Fatalf("gate: %d", w.Code)
	}
	if got := strings.Join((*calls)[0][1:], " "); !strings.HasSuffix(got, "-b "+filepath.Join(s.dir, "limator-baseline.json")) {
		t.Fatalf("gate args: %s", got)
	}
	if w := do(s, "POST", "/run?t=secret", "a=header&file=a.go&text=", ""); w.Code != http.StatusBadRequest {
		t.Fatalf("header without text: %d", w.Code)
	}
	if w := do(s, "POST", "/run?t=secret", "a=header&file=a.go&text=a.go+adds+numbers.", ""); w.Code != http.StatusOK || (*calls)[1][1] != "header" {
		t.Fatalf("header: %d %v", w.Code, *calls)
	}
}
