package main

import (
	"encoding/json"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const dirty = `package demo

import "database/sql"

// ronde 17 moved this
func load(db *sql.DB) []string {
	var out []string
	rows, _ := db.Query("SELECT a")
	defer rows.Close()
	for rows.Next() {
		var s string
		if rows.Scan(&s) == nil {
			out = append(out, s)
		}
	}
	_ = db.Ping()
	return out
}
`

const clean = `// Package demo loads names.
package demo

import "database/sql"

func load(db *sql.DB) ([]string, error) {
	var out []string
	rows, err := db.Query("SELECT a")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}
`

func count(fs []Finding) map[string]int {
	m := map[string]int{}
	for _, f := range fs {
		m[f.Rule]++
	}
	return m
}

func TestDirtyGo(t *testing.T) {
	pats := []*regexp.Regexp{regexp.MustCompile(`ronde \d+`)}
	got := count(checkGo("a.go", []byte(dirty), pats))
	for _, id := range []string{"L001", "L002", "L003", "L004", "L006"} {
		if got[id] != 1 {
			t.Errorf("%s: got %d, want 1", id, got[id])
		}
	}
}

func TestCleanGo(t *testing.T) {
	pats := []*regexp.Regexp{regexp.MustCompile(`ronde \d+`)}
	if got := checkGo("a.go", []byte(clean), pats); len(got) != 0 {
		t.Errorf("clean file has findings: %v", got)
	}
}

func TestParseError(t *testing.T) {
	if got := count(checkGo("a.go", []byte("package"), nil)); got["L000"] != 1 {
		t.Errorf("L000: got %d, want 1", got["L000"])
	}
}

func TestText(t *testing.T) {
	cfg := Config{MaxFileLines: 3, MaxLineLength: 10}
	src := "ok\nzero" + string(rune(0x200B)) + "width\n" + strings.Repeat("x", 11) + "\nlast\n"
	got := count(checkText("a.ts", []byte(src), cfg))
	for _, id := range []string{"L005", "L007", "L008"} {
		if got[id] != 1 {
			t.Errorf("%s: got %d, want 1", id, got[id])
		}
	}
}

func TestScanIsDeterministic(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.go"), []byte(dirty), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "vendor"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "vendor", "b.go"), []byte(dirty), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(filepath.Join(dir, "limator.json"), false)
	if err != nil {
		t.Fatal(err)
	}
	a, err := scan(dir, cfg)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := scan(dir, cfg)
	if a.Files != 1 {
		t.Errorf("files: got %d, want 1 (vendor must be skipped)", a.Files)
	}
	if a.Hash != b.Hash || a.Hash == "" {
		t.Errorf("hash not stable: %q vs %q", a.Hash, b.Hash)
	}
}

func TestGateRatchet(t *testing.T) {
	base := filepath.Join(t.TempDir(), "base.json")
	rep := &Report{Rules: rules, Counts: map[string]int{"L004": 5}}
	if code, err := gate(rep, base); code != 0 || err != nil {
		t.Fatalf("first run: %d %v", code, err)
	}
	rep.Counts["L004"] = 6
	if code, _ := gate(rep, base); code != 1 {
		t.Errorf("worse: got %d, want 1", code)
	}
	rep.Counts["L004"] = 3
	if code, _ := gate(rep, base); code != 0 {
		t.Errorf("better: got %d, want 0", code)
	}
	rep.Counts["L004"] = 4
	if code, _ := gate(rep, base); code != 1 {
		t.Errorf("ratchet did not tighten: got %d, want 1", code)
	}
}

func TestNoNetworkImports(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range files {
		f, err := parser.ParseFile(token.NewFileSet(), name, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range f.Imports {
			p := strings.Trim(imp.Path.Value, `"`)
			if p == "net" || strings.HasPrefix(p, "net/") || p == "os/exec" || p == "syscall" {
				t.Errorf("%s imports %s", name, p)
			}
		}
	}
}

func TestSkipGlob(t *testing.T) {
	if !matchAny([]string{"wt-*"}, "wt-k9") || matchAny([]string{"wt-*"}, "gateway") {
		t.Error("glob skip is wrong")
	}
	if checkSkip([]string{"[bad"}) == nil {
		t.Error("bad pattern accepted")
	}
}

func writeCfg(t *testing.T, dir, body string) (Config, error) {
	t.Helper()
	p := filepath.Join(dir, "limator.json")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return loadConfig(p, true)
}

func TestDataRuleAndException(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{"a.tsx": "<div style={{color: 1}} />\n<p>ok</p>\n", "b.tsx": "<div style={{color: 2}} />\n"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cfg, err := writeCfg(t, dir, `{"rules":[{"id":"X001","name":"inline-style","pattern":"style=\\{\\{","files":"*.tsx"}],
		"exceptions":[{"rule":"X001","path":"b.tsx","reason":"legacy screen"},{"rule":"L004","path":"nothing/","reason":"stale"}]}`)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := scan(dir, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Counts["X001"] != 1 || rep.Suppressed["X001"] != 1 || rep.Counts["H002"] != 1 {
		t.Errorf("counts %v suppressed %v", rep.Counts, rep.Suppressed)
	}
}

func TestConfigRejectsBadInput(t *testing.T) {
	for _, body := range []string{
		`{"exceptions":[{"rule":"L004","path":"a.go","reason":" "}]}`,
		`{"rules":[{"id":"L001","pattern":"x"}]}`,
		`{"rules":[{"id":"X1","pattern":"("}]}`,
		`{"imports":[{"id":"E1"}]}`,
		`{"skip_dirs":["[bad"]}`,
	} {
		if _, err := writeCfg(t, t.TempDir(), body); err == nil {
			t.Errorf("accepted: %s", body)
		}
	}
}

func TestImportTool(t *testing.T) {
	dir := t.TempDir()
	im := Import{ID: "E001", Name: "errcheck", File: "tool.txt"}
	if got := count(importTool(dir, im)); got["H001"] != 1 {
		t.Errorf("missing file: %v", got)
	}
	file := filepath.Join(dir, "tool.txt")
	if err := os.WriteFile(file, []byte("a.go:3:5:\tdefer rows.Close()\nsub\\b.go:10: something\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	fs := importTool(dir, im)
	if got := count(fs); got["E001"] != 2 || got["H001"] != 0 {
		t.Errorf("healthy output: %v", got)
	}
	if fs[1].File != "sub/b.go" || fs[1].Line != 10 {
		t.Errorf("second finding: %+v", fs[1])
	}
	if err := os.WriteFile(file, []byte("panic: cannot decode\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := count(importTool(dir, im)); got["H001"] != 1 || got["E001"] != 0 {
		t.Errorf("crashed tool: %v", got)
	}
}

func TestSarif(t *testing.T) {
	rep := &Report{Version: version, Rules: rules, Findings: []Finding{{"L004", "a.go", 3, "call result discarded"}}}
	raw, err := sarif(rep)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Version string
		Runs    []struct {
			Results []struct {
				RuleID string `json:"ruleId"`
			}
		}
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Version != "2.1.0" || len(doc.Runs) != 1 || len(doc.Runs[0].Results) != 1 || doc.Runs[0].Results[0].RuleID != "L004" {
		t.Errorf("unexpected sarif: %s", raw)
	}
}
