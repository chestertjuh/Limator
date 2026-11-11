package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func testServer(t *testing.T) (*server, *[][]string) {
	t.Helper()
	var calls [][]string
	s := &server{dir: "proj", cfg: "cfg.json", token: "secret", host: "127.0.0.1:8765", work: t.TempDir()}
	s.run = func(args ...string) (string, error) {
		calls = append(calls, args)
		for i, a := range args {
			if a == "-o" && i+1 < len(args) {
				if err := os.WriteFile(args[i+1], []byte("<html>report</html>"), 0o644); err != nil {
					return "", err
				}
			}
		}
		return "done", nil
	}
	return s, &calls
}

func do(s *server, method, target, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, target, strings.NewReader(body))
	r.Host = s.host
	if body != "" {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	w := httptest.NewRecorder()
	s.routes().ServeHTTP(w, r)
	return w
}

func TestAccessNeedsTokenAndLocalHost(t *testing.T) {
	s, _ := testServer(t)
	if w := do(s, "GET", "/", ""); w.Code != http.StatusForbidden {
		t.Errorf("no token: %d", w.Code)
	}
	if w := do(s, "GET", "/?t=wrong", ""); w.Code != http.StatusForbidden {
		t.Errorf("wrong token: %d", w.Code)
	}
	r := httptest.NewRequest("GET", "/?t=secret", nil)
	r.Host = "evil.example"
	w := httptest.NewRecorder()
	s.routes().ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("foreign host: %d", w.Code)
	}
	if w := do(s, "GET", "/?t=secret", ""); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Limator") {
		t.Errorf("home: %d", w.Code)
	}
}

func TestActions(t *testing.T) {
	s, calls := testServer(t)
	if w := do(s, "GET", "/run?t=secret", ""); w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET run: %d", w.Code)
	}
	if w := do(s, "POST", "/run?t=secret", "a=fix"); w.Code != http.StatusBadRequest {
		t.Errorf("fix without confirm: %d", w.Code)
	}
	if w := do(s, "POST", "/run?t=secret", "a=delete"); w.Code != http.StatusBadRequest {
		t.Errorf("unknown action: %d", w.Code)
	}
	if len(*calls) != 0 {
		t.Fatalf("scanner ran without a valid request: %v", *calls)
	}
	if w := do(s, "POST", "/run?t=secret", "a=preview"); w.Code != http.StatusOK || w.Body.String() != "done" {
		t.Errorf("preview: %d %q", w.Code, w.Body.String())
	}
	if got := strings.Join((*calls)[0], " "); got != "fix proj -c cfg.json -n yes" {
		t.Errorf("preview ran: %s", got)
	}
	if w := do(s, "POST", "/run?t=secret", "a=fix&confirm=yes"); w.Code != http.StatusOK {
		t.Errorf("fix: %d", w.Code)
	}
	if got := strings.Join((*calls)[1], " "); got != "fix proj -c cfg.json" {
		t.Errorf("fix ran: %s", got)
	}
}

func TestReport(t *testing.T) {
	s, _ := testServer(t)
	if w := do(s, "GET", "/report?t=secret", ""); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "report") {
		t.Errorf("report: %d %q", w.Code, w.Body.String())
	}
}

func TestMarkAsReadAndDocuments(t *testing.T) {
	s, calls := testServer(t)
	s.who = "reviewer"
	for _, body := range []string{"a=read", "a=read&file=a.go", "a=read&file=-o&fn=x", "a=read&file=a.go&fn=-c"} {
		if w := do(s, "POST", "/run?t=secret", body); w.Code != http.StatusBadRequest {
			t.Errorf("%s: %d", body, w.Code)
		}
	}
	if len(*calls) != 0 {
		t.Fatalf("scanner ran on a refused request: %v", *calls)
	}
	if w := do(s, "POST", "/run?t=secret", "a=read&file=a.go&fn=load"); w.Code != http.StatusOK {
		t.Errorf("read: %d", w.Code)
	}
	if got := strings.Join((*calls)[0], " "); got != "read proj -c cfg.json -who reviewer -f a.go -fn load" {
		t.Errorf("read ran: %s", got)
	}
	for _, path := range []string{"/readlist", "/audit"} {
		if w := do(s, "GET", path+"?t=secret", ""); w.Code != http.StatusOK {
			t.Errorf("%s: %d", path, w.Code)
		}
		if w := do(s, "GET", path, ""); w.Code != http.StatusForbidden {
			t.Errorf("%s without token: %d", path, w.Code)
		}
	}
}
